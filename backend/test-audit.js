
const { verifyAuditChain } = require("./audit");

async function main() {
  const result = await verifyAuditChain();
  console.log("Audit chain verification:", result);
  process.exitCode = result.valid ? 0 : 1;
}

main().catch((error) => {
  console.error("Audit verification failed:", error.message);
  process.exitCode = 1;
});
