
const crypto = require("crypto");
const pool = require("./db");

function calculateHash(event) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(event))
    .digest("hex");
}

async function writeAudit({
  actorId = null,
  action,
  documentId = null,
  targetUserId = null,
  outcome,
  details = {},
}) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Prevent concurrent writers from using the same previous hash.
    await client.query(
      "SELECT pg_advisory_xact_lock($1)",
      [741852963]
    );

    const previousResult = await client.query(
      `SELECT entry_hash
       FROM audit_logs
       ORDER BY id DESC
       LIMIT 1`
    );

    const previousHash =
      previousResult.rows[0]?.entry_hash ?? "GENESIS";

    const event = {
      actorId,
      action,
      documentId,
      targetUserId,
      outcome,
      details,
      previousHash,
    };

    const entryHash = calculateHash(event);

    await client.query(
      `INSERT INTO audit_logs (
         actor_id, action, document_id, target_user_id,
         outcome, details, previous_hash, entry_hash
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        actorId,
        action,
        documentId,
        targetUserId,
        outcome,
        JSON.stringify(details),
        previousHash,
        entryHash,
      ]
    );

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function verifyAuditChain() {
  const result = await pool.query(
    `SELECT id, actor_id, action, document_id,
            target_user_id, outcome, details,
            previous_hash, entry_hash
     FROM audit_logs
     ORDER BY id ASC`
  );

  let expectedPreviousHash = "GENESIS";

  for (const row of result.rows) {
    // Each entry must point to the hash of the preceding entry.
    if (row.previous_hash !== expectedPreviousHash) {
      return {
        valid: false,
        failedAtId: row.id,
        reason: "Previous hash does not match",
      };
    }

    // Rebuild the event using the same fields and order as writeAudit().
    const event = {
      actorId: row.actor_id,
      action: row.action,
      documentId: row.document_id,
      targetUserId: row.target_user_id,
      outcome: row.outcome,
      details: row.details,
      previousHash: row.previous_hash,
    };

    const recalculatedHash = calculateHash(event);

    if (recalculatedHash !== row.entry_hash) {
      return {
        valid: false,
        failedAtId: row.id,
        reason: "Entry hash does not match event contents",
      };
    }

    expectedPreviousHash = row.entry_hash;
  }

  return {
    valid: true,
    checkedEntries: result.rows.length,
  };
}

module.exports = { writeAudit, verifyAuditChain };
