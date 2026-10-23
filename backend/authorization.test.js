
const request = require("supertest");
const app = require("./index");
const pool = require("./db");
const crypto = require("crypto");
const { verifyAuditChain } = require("./audit");

describe("TrustVault authorization boundaries", () => {
  let ownerAgent;
  let viewerAgent;
  let adminAgent;
  let documentId;

  const ownerCredentials = {
    email: "owner@trustvault.local",
    password: process.env.SEED_OWNER_PASSWORD,
  };

  const viewerCredentials = {
    email: "viewer@trustvault.local",
    password: process.env.SEED_VIEWER_PASSWORD,
  };

  const adminCredentials = {
    email: "admin@trustvault.local",
    password: process.env.SEED_ADMIN_PASSWORD,
  };

  async function login(agent, credentials) {
    const response = await agent
      .post("/api/auth/login")
      .send(credentials);

    expect(response.status).toBe(200);
  }

  beforeAll(async () => {
    if (
      !ownerCredentials.password ||
      !viewerCredentials.password ||
      !adminCredentials.password
    ) {
      throw new Error(
        "Test passwords are missing. Check the existing backend .env setup."
      );
    }

    ownerAgent = request.agent(app);
    viewerAgent = request.agent(app);
    adminAgent = request.agent(app);

    await login(ownerAgent, ownerCredentials);
    await login(viewerAgent, viewerCredentials);
    await login(adminAgent, adminCredentials);

    // Create a test document through the real API.
    const response = await ownerAgent
      .post("/api/documents")
      .send({
        name: `Authorization test ${Date.now()}`,
        category: "Security Tests",
      });

    expect(response.status).toBe(201);
    documentId = response.body.document.id;
  });

  afterAll(async () => {
    // Delete only the document created by this test suite.
    if (documentId) {
      await pool.query(
        "DELETE FROM documents WHERE id = $1",
        [documentId]
      );
    }

    await pool.end();
  });

  test("unauthenticated users cannot read document metadata", async () => {
    const response = await request(app)
      .get(`/api/documents/${documentId}`);

    expect([401, 403, 404]).toContain(response.status);
  });

  test("admin cannot read document metadata", async () => {
    const response = await adminAgent
      .get(`/api/documents/${documentId}`);

    expect([403, 404]).toContain(response.status);
  });

  test("admin cannot download a document", async () => {
    const response = await adminAgent
      .get(`/api/documents/${documentId}/download`);

    expect([403, 404]).toContain(response.status);
  });

  test("admin cannot edit document metadata", async () => {
    const response = await adminAgent
      .put(`/api/documents/${documentId}`)
      .send({ name: "Unauthorized admin edit" });

    expect([403, 404]).toContain(response.status);
  });

  test("admin cannot delete a document", async () => {
    const response = await adminAgent
      .delete(`/api/documents/${documentId}`);

    expect([403, 404]).toContain(response.status);
  });

  test("viewer without permission cannot read another user's document", async () => {
    const response = await viewerAgent
      .get(`/api/documents/${documentId}`);

    expect([403, 404]).toContain(response.status);
  });

  test("viewer cannot grant document permissions", async () => {
    const response = await viewerAgent
      .post(`/api/documents/${documentId}/permissions`)
      .send({
        userEmail: "admin@trustvault.local",
        permission: "read",
      });

    expect([403, 404]).toContain(response.status);
  });
  test("revoking edit permission immediately blocks further edits", async () => {
    const viewerResult = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      ["viewer@trustvault.local"]
    );
    const viewerId = viewerResult.rows[0].id;

    const grant = await ownerAgent
      .post(`/api/documents/${documentId}/permissions`)
      .send({
        userEmail: "viewer@trustvault.local",
        permission: "edit",
      });

    expect(grant.status).toBe(201);

    const allowedEdit = await viewerAgent
  .put(`/api/documents/${documentId}`)
  .send({
    name: "Edit Before Revocation",
    category: "Security Tests",
  });

    expect(allowedEdit.status).toBe(200);

    const revoke = await ownerAgent.delete(
      `/api/documents/${documentId}/permissions/${viewerId}`
    );

    expect(revoke.status).toBe(200);

    const deniedEdit = await viewerAgent
  .put(`/api/documents/${documentId}`)
  .send({
    name: "Edit After Revocation",
    category: "Security Tests",
  });

    expect([403, 404]).toContain(deniedEdit.status);

    const finalDocument = await ownerAgent.get(
      `/api/documents/${documentId}`
    );

    expect(finalDocument.status).toBe(200);
    expect(finalDocument.body.document.name).toBe("Edit Before Revocation");
  });
  test("admin can access audit logs and integrity status", async () => {
    const response = await adminAgent.get("/api/admin/audit-logs");
    expect(response.status).toBe(200);
    expect(Array.isArray(response.body.events)).toBe(true);
    expect(response.body).toHaveProperty("integrity");
    expect(response.body.integrity).toHaveProperty("valid");
  });

  test("owner cannot access admin audit logs", async () => {
    const response = await ownerAgent.get("/api/admin/audit-logs");

    expect(response.status).toBe(403);
  });

  test("viewer cannot access admin audit logs", async () => {
    const response = await viewerAgent.get("/api/admin/audit-logs");

    expect(response.status).toBe(403);
  });

  test("unauthenticated user cannot access admin audit logs", async () => {
    const response = await request(app).get("/api/admin/audit-logs");
    expect(response.status).toBe(401);
  });
  
test("audit verifier detects a modified event without changing production data", async () => {
  const stableStringify = (value) => {
    if (value === null || typeof value !== "object") {
      return JSON.stringify(value);
    }

    if (Array.isArray(value)) {
      return `[${value.map(stableStringify).join(",")}]`;
    }

    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${stableStringify(value[key])}`
      )
      .join(",")}}`;
  };

  const originalEvent = {
    actorId: "257512f5-a9a9-4cd3-bd7a-000000000001",
    action: "document.read",
    documentId: "a4712e45-d50f-48b5-9390-13de04ce68ea",
    targetUserId: null,
    outcome: "success",
    details: { filename: "original.pdf" },
    previousHash: "GENESIS",
  };

  const originalHash = crypto
    .createHash("sha256")
    .update(stableStringify(originalEvent))
    .digest("hex");

  // Simulate stored data whose details were altered after hashing.
  const tamperedRow = {
    id: "1",
    actor_id: originalEvent.actorId,
    action: originalEvent.action,
    document_id: originalEvent.documentId,
    target_user_id: null,
    outcome: originalEvent.outcome,
    details: { filename: "tampered.pdf" },
    previous_hash: "GENESIS",
    entry_hash: originalHash,
  };

  const querySpy = jest
    .spyOn(pool, "query")
    .mockResolvedValueOnce({ rows: [tamperedRow] });

  try {
    const result = await verifyAuditChain();

    expect(result.valid).toBe(false);
    expect(result.failedAtId).toBe("1");
    expect(result.reason).toBe(
      "Entry hash does not match event contents"
    );
  } finally {
    querySpy.mockRestore();
  }
});

  test("admin role check succeeds without granting document access", async () => {
    const response = await adminAgent.get("/api/test/admin");

    expect(response.status).toBe(200);
  });
});
