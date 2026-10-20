
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const pool = require("./db");
const bcrypt = require("bcrypt");
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

app.listen(PORT, () => {
  console.log(`TrustVault server running at http://localhost:${PORT}`);
});

