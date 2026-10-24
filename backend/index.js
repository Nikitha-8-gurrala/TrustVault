
const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const pool = require("./db");
const bcrypt = require("bcrypt");
const { writeAudit, verifyAuditChain } = require("./audit");
const uploadRouter = require("./uploads");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);

app.use(express.json());
app.use(
  session({
    store: new pgSession({
      pool,
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
  maxAge: 1000 * 60 * 60,
},
  })
);
// Login endpoint

const LOGIN_FAILURE_LIMIT = 5;
const LOGIN_WINDOW_MINUTES = 10;

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        error: "Email and password are required.",
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
        // Enforce a five-minute cooldown after the fifth failed login.
    const COOLDOWN_MINUTES = 5;

    const securityStateResult = await pool.query(
      `SELECT failed_attempts, alert_triggered_at
       FROM public.login_security_events
       WHERE email_normalized = $1`,
      [normalizedEmail]
    );

    const securityState = securityStateResult.rows[0];

    if (securityState?.failed_attempts >= LOGIN_FAILURE_LIMIT &&
        securityState.alert_triggered_at) {
      const lockoutEndsAt =
        new Date(securityState.alert_triggered_at).getTime() +
        COOLDOWN_MINUTES * 60 * 1000;

      const remainingMs = lockoutEndsAt - Date.now();

      if (remainingMs > 0) {
        const remainingSeconds = Math.ceil(remainingMs / 1000);

        await writeAudit({
          actorId: null,
          action: "security.login_blocked",
          outcome: "denied",
          details: {
            reason: "login_cooldown",
            cooldownMinutes: COOLDOWN_MINUTES,
            remainingSeconds,
          },
        });

        return res.status(429).json({
          error: `Too many failed attempts. Try again in ${remainingSeconds} seconds.`,
        });
      }

      // Cooldown expired: start a fresh failure cycle.
      await pool.query(
        `UPDATE public.login_security_events
         SET failed_attempts = 0,
             window_started_at = NOW(),
             alert_triggered_at = NULL,
             resolved_at = NOW(),
             updated_at = NOW()
         WHERE email_normalized = $1`,
        [normalizedEmail]
      );
    }
    const result = await pool.query(
      `SELECT id, email, password_hash, role
       FROM users
       WHERE email = $1`,
      [normalizedEmail]
    );

    const user = result.rows[0];

    const passwordMatches = user
      ? await bcrypt.compare(password, user.password_hash)
      : false;

    if (!user || !passwordMatches) {
      // Use a keyed fingerprint instead of storing the email in audit details.
      const emailFingerprint = require("crypto")
        .createHmac("sha256", process.env.SESSION_SECRET)
        .update(normalizedEmail)
        .digest("hex")
        .slice(0, 16);

      let failedAttempts;
      let alertTriggered = false;

      const client = await pool.connect();

      try {
        await client.query("BEGIN");

        // Serialize updates for this email to avoid duplicate alerts.
        await client.query(
          "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
          [normalizedEmail]
        );

        const counterResult = await client.query(
          `INSERT INTO public.login_security_events (
             email_normalized,
             failed_attempts,
             window_started_at,
             last_failed_at,
             alert_triggered_at,
             resolved_at,
             updated_at
           )
           VALUES ($1, 1, NOW(), NOW(), NULL, NULL, NOW())
           ON CONFLICT (email_normalized)
           DO UPDATE SET
             failed_attempts = CASE
               WHEN public.login_security_events.window_started_at
                    < NOW() - ($2 * INTERVAL '1 minute')
               THEN 1
               ELSE public.login_security_events.failed_attempts + 1
             END,
             window_started_at = CASE
               WHEN public.login_security_events.window_started_at
                    < NOW() - ($2 * INTERVAL '1 minute')
               THEN NOW()
               ELSE public.login_security_events.window_started_at
             END,
             last_failed_at = NOW(),
             alert_triggered_at = CASE
               WHEN public.login_security_events.window_started_at
                    < NOW() - ($2 * INTERVAL '1 minute')
               THEN NULL
               ELSE public.login_security_events.alert_triggered_at
             END,
             resolved_at = NULL,
             updated_at = NOW()
           RETURNING id, failed_attempts, alert_triggered_at`,
          [normalizedEmail, LOGIN_WINDOW_MINUTES]
        );

        const counter = counterResult.rows[0];
        failedAttempts = counter.failed_attempts;

        if (
          failedAttempts >= LOGIN_FAILURE_LIMIT &&
          !counter.alert_triggered_at
        ) {
          const alertResult = await client.query(
            `UPDATE public.login_security_events
             SET alert_triggered_at = NOW(),
                 updated_at = NOW()
             WHERE id = $1
               AND alert_triggered_at IS NULL
             RETURNING id, failed_attempts`,
            [counter.id]
          );

          alertTriggered = alertResult.rowCount === 1;
        }

        await client.query("COMMIT");
      } catch (trackingError) {
        await client.query("ROLLBACK").catch(() => {});
        throw trackingError;
      } finally {
        client.release();
      }

      // Record the denied login in the existing audit chain.
      await writeAudit({
        actorId: null,
        action: "auth.login.failed",
        outcome: "denied",
        details: {
          reason: "invalid_credentials",
          emailFingerprint,
        },
      });

      if (alertTriggered) {
        await writeAudit({
          actorId: null,
          action: "security.login_threshold",
          outcome: "denied",
          details: {
            emailFingerprint,
            failedAttempts,
            windowMinutes: LOGIN_WINDOW_MINUTES,
          },
        });
      }

      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }
      req.session.regenerate ((sessionError) => {
      if (sessionError) {
        console.error("Session creation failed.");
        return res.status(500).json({
          error: "Unable to create session.",
        });
      }

      req.session.userId = user.id;

      req.session.save(async (saveError) => {
        if (saveError) {
          console.error("Session save failed.");
          return res.status(500).json({
            error: "Unable to save session.",
          });
        }

        // Clear failed-login tracking only after the session is saved.
        try {
          await pool.query(
            `UPDATE public.login_security_events
             SET failed_attempts = 0,
                 window_started_at = NOW(),
                 alert_triggered_at = NULL,
                 resolved_at = NOW(),
                 updated_at = NOW()
             WHERE email_normalized = $1`,
            [normalizedEmail]
          );
        } catch (resetError) {
          // Don't report login failure after the session was saved.
          console.error("Login counter reset failed:", resetError.message);
        }

        return res.status(200).json({
          message: "Login successful.",
          user: {
            id: user.id,
            email: user.email,
            role: user.role,
          },
        });
      });
    });
  } catch (error) {
    console.error("Login failed:", error.message);
    return res.status(500).json({
      error: "An unexpected error occurred.",
    });
  }
});

// Authentication middleware
async function requireAuth(req, res, next) {
  try {
    if (!req.session.userId) {
      return res.status(401).json({
        error: "Authentication required.",
      });
    }

    const result = await pool.query(
      "SELECT id, email, role FROM users WHERE id = $1",
      [req.session.userId]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Authentication required.",
      });
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    console.error("Authentication check failed:", error.message);
    return res.status(500).json({
      error: "Unable to verify authentication.",
    });
  }
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: "You do not have permission to perform this action.",
      });
    }

    next();
  };
}

app.get(
  "/api/admin/audit-logs",
  requireAuth,
  requireRole("admin"),
  async (req, res) => {
    try {
      const requestedLimit = Number.parseInt(req.query.limit, 10);
      const limit = Number.isInteger(requestedLimit)
        ? Math.min(Math.max(requestedLimit, 1), 200)
        : 100;

      const [logs, integrity] = await Promise.all([
        pool.query(
  `SELECT
     a.id,
     a.action,
     a.document_id,
     a.target_user_id,
     a.outcome,
     a.details,
     a.previous_hash,
     a.entry_hash,
     a.created_at,
     actor.email AS actor_email,
     target.email AS target_email
   FROM public.audit_chain_logs a
   LEFT JOIN users actor ON actor.id = a.actor_id
   LEFT JOIN users target ON target.id = a.target_user_id
   ORDER BY a.id DESC
   LIMIT $1`,
  [limit]
),
        verifyAuditChain(),
      ]);

      res.json({
        events: logs.rows,
        integrity,
      });
    } catch (error) {
      console.error("Admin audit log retrieval failed:", error);
      res.status(500).json({
        error: "Unable to retrieve audit logs",
      });
    }
  }
);

app.use(
  "/api/documents/upload",
  requireAuth,
  requireRole("owner"),
  uploadRouter
);
// Role authorization test endpoint
app.get(
  "/api/test/admin",
  requireAuth,
  requireRole("admin"),
  (req, res) => {
    res.status(200).json({
      message: "Admin access granted.",
    });
  }
);


 // Create document metadata
app.post(
  "/api/documents",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
  try {
    const { name, category } = req.body;

    if (
      typeof name !== "string" ||
      typeof category !== "string" ||
      !name.trim() ||
      !category.trim()
    ) {
      return res.status(400).json({
        error: "Document name and category are required.",
      });
    }

    const result = await pool.query(
      `INSERT INTO documents (owner_id, name, category)
       VALUES ($1, $2, $3)
       RETURNING id, owner_id, name, category, created_at`,
      [req.user.id, name.trim(), category.trim()]
    );

    return res.status(201).json({
      message: "Document created successfully.",
      document: result.rows[0],
    });
  } catch (error) {
    console.error("Document creation failed:", error.message);
    return res.status(500).json({
      error: "Unable to create document.",
    });
  }
});


 // Grant a named user access to an owned document
app.post(
  "/api/documents/:id/permissions",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      const { userEmail, permission } = req.body;

      if (
        typeof userEmail !== "string" ||
        !userEmail.trim() ||
        !["read", "edit"].includes(permission)
      ) {
        return res.status(400).json({
          error: "A recipient email and valid permission (read or edit) are required.",
        });
      }

      const documentResult = await pool.query(
        "SELECT id FROM documents WHERE id = $1 AND owner_id = $2",
        [req.params.id, req.user.id]
      );

      if (documentResult.rows.length === 0) {
  await writeAudit({
    actorId: req.user.id,
    action: "permission.grant",
    documentId: req.params.id,
    outcome: "denied",
    details: { reason: "document_not_found" },
  });

  return res.status(404).json({
    error: "Document not found.",
  });
}

      const recipientResult = await pool.query(
        "SELECT id, role FROM users WHERE email = $1",
        [userEmail.trim().toLowerCase()]
      );

      const recipient = recipientResult.rows[0];

if (!recipient || recipient.role === "admin") {
  await writeAudit({
    actorId: req.user.id,
    action: "permission.grant",
    documentId: req.params.id,
    targetUserId: recipient?.id ?? null,
    outcome: "denied",
    details: { reason: "invalid_recipient" },
  });

  return res.status(400).json({
    error: "A valid non-admin recipient is required.",
  });
}
if (recipient.id === req.user.id) {
  await writeAudit({
    actorId: req.user.id,
    action: "permission.grant",
    documentId: req.params.id,
    targetUserId: recipient.id,
    outcome: "denied",
    details: { reason: "self_grant" },
  });

  return res.status(400).json({
    error: "You cannot grant access to yourself.",
  });
}


      const grantResult = await pool.query(
        `INSERT INTO document_permissions
           (document_id, user_id, permission, granted_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (document_id, user_id)
         DO UPDATE SET
           permission = EXCLUDED.permission,
           granted_by = EXCLUDED.granted_by,
           created_at = NOW()
         RETURNING id, document_id, user_id, permission, granted_by, created_at`,
        [req.params.id, recipient.id, permission, req.user.id]
      );
      await writeAudit({
  actorId: req.user.id,
  action: "permission.grant",
  documentId: req.params.id,
  targetUserId: recipient.id,
  outcome: "success",
  details: {
    permission,
  },
});

      return res.status(201).json({
        message: "Document permission granted successfully.",
        grant: grantResult.rows[0],
      });
    } catch (error) {
      console.error("Permission grant failed:", error.message);
      return res.status(500).json({
        error: "Unable to grant document permission.",
      });
    }
  }
);


 // Revoke a named user's access to an owned document
app.delete(
  "/api/documents/:id/permissions/:userId",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `DELETE FROM document_permissions AS p
         USING documents AS d
         WHERE p.document_id = d.id
           AND p.document_id = $1
           AND p.user_id = $2
           AND d.owner_id = $3
         RETURNING p.id`,
        [req.params.id, req.params.userId, req.user.id]
      );

if (result.rows.length === 0) {
  await writeAudit({
    actorId: req.user.id,
    action: "permission.revoke",
    documentId: req.params.id,
    targetUserId: req.params.userId,
    outcome: "denied",
    details: { reason: "document_or_grant_not_found" },
  });

  return res.status(404).json({
    error: "Document or permission grant not found.",
  });
}

      await writeAudit({
  actorId: req.user.id,
  action: "permission.revoke",
  documentId: req.params.id,
  targetUserId: req.params.userId,
  outcome: "success",
});

      return res.status(200).json({
        message: "Document access revoked successfully.",
      });
    } catch (error) {
      console.error("Permission revocation failed:", error.message);
      return res.status(500).json({
        error: "Unable to revoke document access.",
      });
    }
  }
);

app.get(
  "/api/documents/:id/permissions",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT p.user_id, u.email, p.permission, p.created_at
         FROM document_permissions AS p
         JOIN users AS u ON u.id = p.user_id
         JOIN documents AS d ON d.id = p.document_id
         WHERE p.document_id = $1
           AND d.owner_id = $2
         ORDER BY p.created_at DESC`,
        [req.params.id, req.user.id]
      );

      return res.status(200).json({
        permissions: result.rows,
      });
    } catch (error) {
      console.error("Permission listing failed:", error.message);
      return res.status(500).json({
        error: "Unable to retrieve document permissions.",
      });
    }
  }
);

 // List documents owned by the logged-in user
app.get(
  "/api/documents",
  requireAuth,
  requireRole("owner", "viewer"),
  async (req, res) => {  try {
    /*console.log("DOCUMENT LIST DEBUG:", {
  userId: req.user.id,
  role: req.user.role,
});*/
const result = await pool.query(
  `SELECT DISTINCT
     d.id,
     d.owner_id,
     d.name,
     d.category,
     d.created_at,
     CASE
       WHEN d.owner_id = $1 THEN 'owner'
       ELSE p.permission
     END AS access_level
   FROM documents d
   LEFT JOIN document_permissions p
     ON p.document_id = d.id
    AND p.user_id = $1
   WHERE d.owner_id = $1
      OR p.permission IN ('read', 'edit')
   ORDER BY d.created_at DESC`,
  [req.user.id]
);


    return res.status(200).json({
      documents: result.rows,
    });
  } catch (error) {
    console.error("Document listing failed:", error.message);
    return res.status(500).json({
      error: "Unable to list documents.",
    });
  }
});

app.get(
  "/api/documents/:id/download",
  requireAuth,
  requireRole("owner", "viewer"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT d.id, d.owner_id, d.storage_path, d.name,
                d.mime_type
         FROM documents d
         LEFT JOIN document_permissions p
           ON p.document_id = d.id
          AND p.user_id = $2
         WHERE d.id = $1
           AND (
             d.owner_id = $2
             OR p.permission IN ('read', 'edit')
           )`,
        [req.params.id, req.user.id]
      );

      const document = result.rows[0];

      if (!document || !document.storage_path) {
        await writeAudit({
          actorId: req.user.id,
          action: "document.download",
          documentId: req.params.id,
          outcome: "denied",
          details: { reason: "not_found_or_no_access" },
        });

        return res.status(404).json({
          error: "Document not found or access denied.",
        });
      }

      const uploadDirectory = path.resolve(__dirname, "uploads");
      const filename = path.basename(document.storage_path);
      const filePath = path.resolve(uploadDirectory, filename);

      if (
  filePath === uploadDirectory ||
  !filePath.startsWith(uploadDirectory + path.sep) ||
  !fs.existsSync(filePath) ||
  !fs.statSync(filePath).isFile()
) {
        await writeAudit({
          actorId: req.user.id,
          action: "document.download",
          documentId: document.id,
          outcome: "denied",
          details: { reason: "stored_file_missing_or_invalid" },
        });

        return res.status(404).json({
          error: "Stored file not found.",
        });
      }

      res.setHeader("Content-Type", document.mime_type || "application/octet-stream");

const inline = req.query.inline === "1";

res.setHeader(
  "Content-Type",
  document.mime_type || "application/pdf"
);

if (inline) {
  res.setHeader(
    "Content-Disposition",
    `inline; filename="${path.basename(document.name).replace(/["\\\r\n]/g, "_")}"`
  );

  return res.sendFile(filePath, async (error) => {
    try {
      await writeAudit({
        actorId: req.user.id,
        action: "document.read",
        documentId: document.id,
        outcome: error ? "denied" : "success",
        details: error
          ? { reason: "preview_failed" }
          : { reason: "preview_completed" },
      });
    } catch (auditError) {
      console.error("Preview audit failed:", auditError.message);
    }

    if (error && !res.headersSent) {
      res.status(500).json({ error: "Unable to preview document." });
    }
  });
}

return res.download(filePath, document.name, async (error) => {
  try {
    await writeAudit({
      actorId: req.user.id,
      action: "document.download",
      documentId: document.id,
      outcome: error ? "denied" : "success",
      details: error
        ? { reason: "transfer_failed" }
        : { reason: "transfer_completed" },
    });
  } catch (auditError) {
    console.error("Download audit failed:", auditError.message);
  }

  if (error && !res.headersSent) {
    res.status(500).json({ error: "Unable to download document." });
  }
});
    } catch (error) {
      console.error("Document download failed:", error.message);

      if (!res.headersSent) {
        return res.status(500).json({
          error: "Unable to download document.",
        });
      }
    }
  }
);


 // Get one document only when the requester has access
// Get one document only when requester has access; audit the outcome
app.get(
  "/api/documents/:id",
  requireAuth,
  requireRole("owner", "viewer"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT DISTINCT d.id, d.owner_id, d.name, d.category, d.created_at
         FROM documents d
         LEFT JOIN document_permissions p
           ON p.document_id = d.id
          AND p.user_id = $2
         WHERE d.id = $1
           AND (
             d.owner_id = $2
             OR p.permission IN ('read', 'edit')
           )`,
        [req.params.id, req.user.id]
      );

      if (result.rows.length === 0) {
        await writeAudit({
          actorId: req.user.id,
          action: "document.read",
          documentId: req.params.id,
          outcome: "denied",
          details: { reason: "not_found_or_no_access" },
        });

        return res.status(404).json({
          error: "Document not found or access denied.",
        });
      }

      await writeAudit({
        actorId: req.user.id,
        action: "document.read",
        documentId: req.params.id,
        outcome: "success",
      });

      return res.status(200).json({
        document: result.rows[0],
      });
    } catch (error) {
      console.error("Document access check failed:", error.message);

      return res.status(500).json({
        error: "Unable to retrieve document.",
      });
    }
  }
);


// Current-user endpoint
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.status(200).json({
    user: req.user,
  });
});

 // Edit document metadata: owner or user with explicit edit permission
app.put(
  "/api/documents/:id",
  requireAuth,
  requireRole("owner", "viewer"),
  async (req, res) => {
    const { name, category } = req.body;

    if (
      typeof name !== "string" ||
      !name.trim() ||
      typeof category !== "string" ||
      !category.trim()
    ) {
      return res.status(400).json({
        error: "Document name and category are required.",
      });
    }

    try {
      const result = await pool.query(
        `UPDATE documents d
         SET name = $1, category = $2
         WHERE d.id = $3
           AND (
             d.owner_id = $4
             OR EXISTS (
               SELECT 1
               FROM document_permissions p
               WHERE p.document_id = d.id
                 AND p.user_id = $4
                 AND p.permission = 'edit'
             )
           )
         RETURNING d.id, d.owner_id, d.name, d.category, d.created_at`,
        [name.trim(), category.trim(), req.params.id, req.user.id]
      );

      if (result.rows.length === 0) {
        await writeAudit({
          actorId: req.user.id,
          action: "document.edit",
          documentId: req.params.id,
          outcome: "denied",
          details: { reason: "not_found_or_no_edit_access" },
        });

        return res.status(404).json({
          error: "Document not found or access denied.",
        });
      }

      await writeAudit({
        actorId: req.user.id,
        action: "document.edit",
        documentId: req.params.id,
        outcome: "success",
      });

      return res.status(200).json({ document: result.rows[0] });
    } catch (error) {
      console.error("Document edit failed:", error.message);
      return res.status(500).json({
        error: "Unable to edit document.",
      });
    }
  }
);

// Delete a document: owner only
app.delete(
  "/api/documents/:id",
  requireAuth,
  requireRole("owner"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, owner_id, storage_path
         FROM documents
         WHERE id = $1 AND owner_id = $2`,
        [req.params.id, req.user.id]
      );

      const document = result.rows[0];

      if (!document) {
        await writeAudit({
          actorId: req.user.id,
          action: "document.delete",
          documentId: req.params.id,
          outcome: "denied",
          details: { reason: "not_found_or_not_owner" },
        });

        return res.status(404).json({
          error: "Document not found or access denied.",
        });
      }

      // Remove the database record first; never use a client-supplied path.
      await pool.query(
        "DELETE FROM documents WHERE id = $1 AND owner_id = $2",
        [document.id, req.user.id]
      );

      const uploadDirectory = path.resolve(__dirname, "uploads");
      const filename = path.basename(document.storage_path || "");
      const filePath = path.resolve(uploadDirectory, filename);

      if (
        filename &&
        filePath.startsWith(uploadDirectory + path.sep) &&
        fs.existsSync(filePath) &&
        fs.statSync(filePath).isFile()
      ) {
        fs.unlinkSync(filePath);
      }

      await writeAudit({
        actorId: req.user.id,
        action: "document.delete",
        documentId: document.id,
        outcome: "success",
      });

      return res.status(200).json({
        message: "Document deleted.",
      });
    } catch (error) {
      console.error("Document deletion failed:", error.message);
      return res.status(500).json({
        error: "Unable to delete document.",
      });
    }
  }
);

 // Logout endpoint
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error("Logout failed.");
      return res.status(500).json({
        error: "Unable to log out.",
      });
    }

    res.clearCookie("connect.sid", {
      httpOnly: true,
      sameSite: "none",
      secure: process.env.NODE_ENV === "production",
    });

    return res.status(200).json({
      message: "Logout successful.",
    });
  });
});

// Root endpoint
app.get("/", (req, res) => {
  res.status(200).json({
    message: "TrustVault backend is running",
    status: "success",
  });
});

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "TrustVault API",
    timestamp: new Date().toISOString(),
  });
});

if (require.main === module) {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`TrustVault API running on port ${PORT}`);
  });
}

module.exports = app;

