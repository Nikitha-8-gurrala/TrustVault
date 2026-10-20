const pool = require("./db");

async function testConnection() {
  try {
    const result = await pool.query("SELECT 1 AS test");

    console.log("Database connection successful:", result.rows[0].test === 1);
  } catch {
    console.error(
      "Database connection failed. Check your .env and Neon settings."
    );
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

testConnection();