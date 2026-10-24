
const crypto = require("crypto");
const pool = require("./db");

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(value).sort();

  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function calculateHash(event) {
  return crypto
    .createHash("sha256")
    .update(stableStringify(event))
    .digest("hex");
}

async function main() {
  const result = await pool.query(`
    SELECT id, actor_id, action, document_id,
           target_user_id, outcome, details,
           previous_hash, entry_hash
    FROM public.audit_logs_backup_20261022
    ORDER BY id ASC
  `);

  if (result.rows.length === 0) {
    console.log("FAIL: Backup is empty.");
    return;
  }

  let expectedPreviousHash = "GENESIS";

  for (const row of result.rows) {
    if (row.previous_hash !== expectedPreviousHash) {
      console.log("CHAIN LINK FAILURE", {
        id: row.id,
        expectedPreviousHash,
        storedPreviousHash: row.previous_hash,
      });
      return;
    }

    const toId = (value) =>
      value === null || value === undefined ? null : String(value);

    const event = {
      actorId: toId(row.actor_id),
      action: row.action,
      documentId: toId(row.document_id),
      targetUserId: toId(row.target_user_id),
      outcome: row.outcome,
      details: row.details,
      previousHash: row.previous_hash,
    };

    const recalculatedHash = calculateHash(event);

    if (recalculatedHash !== row.entry_hash) {
      console.log("ENTRY HASH FAILURE", {
        id: row.id,
        action: row.action,
        storedHash: row.entry_hash,
        recalculatedHash,
      });
      return;
    }

    expectedPreviousHash = row.entry_hash;
  }

  console.log("PASS: Entire backup chain verified.", {
    valid: true,
    checkedEntries: result.rows.length,
    firstId: result.rows[0].id,
    lastId: result.rows[result.rows.length - 1].id,
  });
}

main()
  .catch((error) => {
    console.error("Verification failed to run:", error.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await pool.end();
  });
