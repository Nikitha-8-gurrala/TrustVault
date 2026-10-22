
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const pool = require("./db");
const bcrypt = require("bcrypt");
const { writeAudit } = require("./audit");
require("dotenv").config();

const app = express();
const PORT = 3000;

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
      secure: false,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60,
    },
  })
);
// Login endpoint
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

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

    const result = await pool.query(
      `SELECT id, email, password_hash, role
       FROM users
       WHERE email = $1`,
      [email.trim().toLowerCase()]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "Invalid email or password.",
      });
    }

    req.session.regenerate((sessionError) => {
      if (sessionError) {
        console.error("Session creation failed.");
        return res.status(500).json({
          error: "Unable to create session.",
        });
      }

      req.session.userId = user.id;

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save failed.");
          return res.status(500).json({
            error: "Unable to save session.",
          });
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
        return res.status(400).json({
          error: "A valid non-admin recipient is required.",
        });
      }

      if (recipient.id === req.user.id) {
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

 // List documents owned by the logged-in user
app.get(
  "/api/documents",
  requireAuth,
  requireRole("owner", "viewer"),
  async (req, res) => {  try {
const result = await pool.query(
  `SELECT DISTINCT d.id, d.owner_id, d.name, d.category, d.created_at
   FROM documents d
   LEFT JOIN document_permissions p
     ON p.document_id = d.id
    AND p.user_id = $1
   WHERE d.owner_id = $1
      OR p.user_id = $1
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
      sameSite: "lax",
      secure: false,
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
  app.listen(PORT, () => {
    console.log(`TrustVault API running on port ${PORT}`);
  });
}

module.exports = app;

