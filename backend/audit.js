
const crypto = require("crypto");
const pool = require("./db");

const VALID_OUTCOMES = new Set(["success", "denied"]);

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(value).sort();

  return `{${keys
    .map(
      (key) =>
        `${JSON.stringify(key)}:${stableStringify(value[key])}`
    )
    .join(",")}}`;
}

function toId(value) {
  return value === undefined || value === null
    ? null
    : String(value);
}

function calculateHash(event) {
  return crypto
    .createHash("sha256")
    .update(stableStringify(event))
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
  // Validate input before opening a database transaction.
  if (typeof action !== "string" || !action.trim()) {
    throw new Error("Audit action is required.");
  }

  if (!VALID_OUTCOMES.has(outcome)) {
    throw new Error(
      'Invalid audit outcome. Use "success" or "denied".'
    );
  }

  if (
    details === null ||
    typeof details !== "object" ||
    Array.isArray(details)
  ) {
    throw new Error("Audit details must be an object.");
  }

  const client = await pool.connect();
  let transactionStarted = false;

  try {
    await client.query("BEGIN");
    transactionStarted = true;

    // Serialize chain writes so concurrent events cannot share
    // the same previous hash.
    await client.query(
      "SELECT pg_advisory_xact_lock($1)",
      [741852963]
    );

    const previousResult = await client.query(
      `SELECT entry_hash
       FROM public.audit_chain_logs
       ORDER BY id DESC
       LIMIT 1`
    );

    const previousHash =
      previousResult.rows[0]?.entry_hash ?? "GENESIS";

    // Preserve the existing hash format for compatibility
    // with already-written audit entries.
    const event = {
      actorId: toId(actorId),
      action,
      documentId: toId(documentId),
      targetUserId: toId(targetUserId),
      outcome,
      details: JSON.parse(JSON.stringify(details)),
      previousHash,
    };

    const entryHash = calculateHash(event);

    await client.query(
      `INSERT INTO public.audit_chain_logs
       (
         actor_id,
         action,
         document_id,
         target_user_id,
         outcome,
         details,
         previous_hash,
         entry_hash
       )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        event.actorId,
        event.action,
        event.documentId,
        event.targetUserId,
        event.outcome,
        JSON.stringify(event.details),
        previousHash,
        entryHash,
      ]
    );

    await client.query("COMMIT");
    transactionStarted = false;
  } catch (error) {
    if (transactionStarted) {
      await client.query("ROLLBACK").catch(() => {});
    }

    throw error;
  } finally {
    client.release();
  }
}

async function verifyAuditChain() {
  const result = await pool.query(
    `SELECT
       id,
       actor_id,
       action,
       document_id,
       target_user_id,
       outcome,
       details,
       previous_hash,
       entry_hash
     FROM public.audit_chain_logs
     ORDER BY id ASC`
  );

  if (result.rows.length === 0) {
    return {
      valid: false,
      checkedEntries: 0,
      reason: "No audit entries found; integrity cannot be verified",
    };
  }

  let expectedPreviousHash = "GENESIS";

  for (const row of result.rows) {
    if (row.previous_hash !== expectedPreviousHash) {
      return {
        valid: false,
        failedAtId: row.id,
        reason: "Previous hash does not match",
      };
    }

    const event = {
      actorId: toId(row.actor_id),
      action: row.action,
      documentId: toId(row.document_id),
      targetUserId: toId(row.target_user_id),
      outcome: row.outcome,
      details:
        typeof row.details === "string"
          ? JSON.parse(row.details)
          : row.details,
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

module.exports = {
  writeAudit,
  verifyAuditChain,
};
