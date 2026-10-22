
const request = require("supertest");
const app = require("./index");
const pool = require("./db");

const documentId = "a4712e45-d50f-48b5-9390-13de04ce68ea";

describe("TrustVault security", () => {
  afterAll(async () => {
    await pool.end();
  });

  test("rejects unauthenticated access to /api/auth/me", async () => {
    const response = await request(app).get("/api/auth/me");
    expect(response.status).toBe(401);
  });

  test("rejects unauthenticated document creation", async () => {
    const response = await request(app)
      .post("/api/documents")
      .send({ name: "Unauthorized test", category: "Testing" });

    expect(response.status).toBe(401);
  });

  test("rejects unauthenticated document listing", async () => {
    const response = await request(app).get("/api/documents");
    expect(response.status).toBe(401);
  });

  test("rejects unauthenticated document reads", async () => {
    const response = await request(app).get(`/api/documents/${documentId}`);
    expect(response.status).toBe(401);
  });

  test("rejects unauthenticated permission grants", async () => {
    const response = await request(app)
      .post(`/api/documents/${documentId}/permissions`)
      .send({ email: "viewer@trustvault.local", permission: "read" });

    expect(response.status).toBe(401);
  });

  test("rejects viewers who try to create documents", async () => {
    const viewer = request.agent(app);

    const login = await viewer.post("/api/auth/login").send({
      email: "viewer@trustvault.local",
      password: process.env.SEED_VIEWER_PASSWORD,
    });
    expect(login.status).toBe(200);

    const response = await viewer.post("/api/documents").send({
      name: "Viewer Security Test",
      category: "Testing",
    });

    expect(response.status).toBe(403);
  });

  test("denies a viewer access without a grant", async () => {
    const viewer = request.agent(app);
    await pool.query(
  `DELETE FROM document_permissions
   WHERE document_id = $1
     AND user_id = (
       SELECT id FROM users WHERE email = $2
     )`,
  [documentId, "viewer@trustvault.local"]
);

    const login = await viewer.post("/api/auth/login").send({
      email: "viewer@trustvault.local",
      password: process.env.SEED_VIEWER_PASSWORD,
    });
    expect(login.status).toBe(200);

    const response = await viewer.get(`/api/documents/${documentId}`);
    expect(response.status).toBe(404);
  });

  test("allows a viewer to read after the owner grants read access", async () => {
    const owner = request.agent(app);
    const viewer = request.agent(app);

    const ownerLogin = await owner.post("/api/auth/login").send({
      email: "owner@trustvault.local",
      password: process.env.SEED_OWNER_PASSWORD,
    });
    expect(ownerLogin.status).toBe(200);

    const viewerLogin = await viewer.post("/api/auth/login").send({
      email: "viewer@trustvault.local",
      password: process.env.SEED_VIEWER_PASSWORD,
    });
    expect(viewerLogin.status).toBe(200);

    const grant = await owner
  .post(`/api/documents/${documentId}/permissions`)
  .send({
    userEmail: "viewer@trustvault.local",
    permission: "read",
  });

    //console.log("Grant response:", grant.status, JSON.stringify(grant.body));

    const response = await viewer.get(`/api/documents/${documentId}`);
    expect(response.status).toBe(200);
    expect(response.body.document.id).toBe(documentId);
  });
    test("revoking a viewer's access prevents further reads", async () => {
    const owner = request.agent(app);
    const viewer = request.agent(app);

    const ownerLogin = await owner.post("/api/auth/login").send({
      email: "owner@trustvault.local",
      password: process.env.SEED_OWNER_PASSWORD,
    });
    expect(ownerLogin.status).toBe(200);

    const viewerLogin = await viewer.post("/api/auth/login").send({
      email: "viewer@trustvault.local",
      password: process.env.SEED_VIEWER_PASSWORD,
    });
    expect(viewerLogin.status).toBe(200);

    const grant = await owner
      .post(`/api/documents/${documentId}/permissions`)
      .send({
        userEmail: "viewer@trustvault.local",
        permission: "read",
      });

    expect(grant.status).toBe(201);

    const beforeRevoke = await viewer.get(`/api/documents/${documentId}`);
    expect(beforeRevoke.status).toBe(200);

    const revoke = await owner.delete(
      `/api/documents/${documentId}/permissions/${viewerLogin.body.user.id}`
    );
    expect(revoke.status).toBe(200);

    const afterRevoke = await viewer.get(`/api/documents/${documentId}`);
    expect(afterRevoke.status).toBe(404);
  });
    test("rejects viewers who try to grant document access", async () => {
    const viewer = request.agent(app);

    const login = await viewer.post("/api/auth/login").send({
      email: "viewer@trustvault.local",
      password: process.env.SEED_VIEWER_PASSWORD,
    });

    expect(login.status).toBe(200);

    const response = await viewer
      .post(`/api/documents/${documentId}/permissions`)
      .send({
        userEmail: "owner@trustvault.local",
        permission: "read",
      });

    expect(response.status).toBe(403);
  });
});
