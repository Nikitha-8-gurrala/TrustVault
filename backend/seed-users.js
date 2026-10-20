const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") });

const bcrypt = require("bcrypt");
const pool = require("./db");

const users = [
  {
    email: "admin@trustvault.local",
    password: process.env.SEED_ADMIN_PASSWORD,
    role: "admin",
  },
  {
    email: "owner@trustvault.local",
    password: process.env.SEED_OWNER_PASSWORD,
    role: "owner",
  },
  {
    email: "viewer@trustvault.local",
    password: process.env.SEED_VIEWER_PASSWORD,
    role: "viewer",
  },
];

async function seedUsers() {
  try {
    for (const user of users) {
  if (!user.password) {
    throw new Error(`Missing password for role: ${user.role}`);
  }
}
    for (const user of users) {
      const passwordHash = await bcrypt.hash(user.password, 12);

      await pool.query(
        `INSERT INTO users (email, password_hash, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (email) DO NOTHING`,
        [user.email, passwordHash, user.role]
      );

      console.log(`Seed checked: ${user.email}`);
    }

    console.log("User seeding completed.");
  } catch (error) {
    console.error("Could not seed users:", error.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

seedUsers();