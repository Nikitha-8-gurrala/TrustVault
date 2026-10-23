
const fs = require("fs");
const path = require("path");
const request = require("supertest");
const app = require("./index");
const pool = require("./db");

const documentId = "a4712e45-d50f-48b5-9390-13de04ce68ea";

describe("TrustVault security", () => {

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
  test("rejects unauthenticated file uploads", async () => {
  const response = await request(app)
    .post("/api/documents/upload")
    .field("name", "Test PDF")
    .field("category", "Testing");

  expect(response.status).toBe(401);
});

test("rejects viewer file uploads", async () => {
  const viewer = request.agent(app);

  const login = await viewer.post("/api/auth/login").send({
    email: "viewer@trustvault.local",
    password: process.env.SEED_VIEWER_PASSWORD,
  });

  expect(login.status).toBe(200);

  const response = await viewer
    .post("/api/documents/upload")
    .field("name", "Viewer Upload Test")
    .field("category", "Testing");

  expect(response.status).toBe(403);
});

test("allows an owner to upload a PDF", async () => {
  const owner = request.agent(app);

  const login = await owner.post("/api/auth/login").send({
    email: "owner@trustvault.local",
    password: process.env.SEED_OWNER_PASSWORD,
  });

  expect(login.status).toBe(200);

  const response = await owner
    .post("/api/documents/upload")
    .field("name", "Upload Test PDF")
    .field("category", "Testing")
    .attach(
      "document",
      Buffer.from("%PDF-1.4\nTrustVault upload test\n%%EOF"),
      {
        filename: "sample.pdf",
        contentType: "application/pdf",
      }
    );

  expect(response.status).toBe(201);
  expect(response.body.document.id).toBeDefined();

  const saved = await pool.query(
    "SELECT storage_path, mime_type, size_bytes FROM documents WHERE id = $1",
    [response.body.document.id]
  );

  expect(saved.rows).toHaveLength(1);
  expect(saved.rows[0].storage_path).toBeTruthy();
  expect(saved.rows[0].mime_type).toBe("application/pdf");
  expect(Number(saved.rows[0].size_bytes)).toBeGreaterThan(0);

  const storedFile = path.join(
    __dirname,
    "uploads",
    saved.rows[0].storage_path
  );

  expect(fs.existsSync(storedFile)).toBe(true);

  // Clean up the test document and file.
  await pool.query("DELETE FROM documents WHERE id = $1", [
    response.body.document.id,
  ]);
  fs.unlinkSync(storedFile);
});

test("downloads are allowed for owners and granted viewers, then denied after revocation", async () => {
  const owner = request.agent(app);
  const viewer = request.agent(app);
  let documentId;
  let storedFile;

  try {
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

    // Upload a real test file.
    const upload = await owner
      .post("/api/documents/upload")
      .field("name", "Download Test PDF")
      .field("category", "Testing")
      .attach("document", Buffer.from("%PDF-1.4\nDownload test\n%%EOF"), {
        filename: "download-test.pdf",
        contentType: "application/pdf",
      });

    expect(upload.status).toBe(201);
    documentId = upload.body.document.id;

    const saved = await pool.query(
      "SELECT storage_path FROM documents WHERE id = $1",
      [documentId]
    );
    expect(saved.rows).toHaveLength(1);

    storedFile = path.join(__dirname, "uploads", saved.rows[0].storage_path);

    // The owner can download their own file.
    const ownerDownload = await owner.get(
      `/api/documents/${documentId}/download`
    );
    expect(ownerDownload.status).toBe(200);
    expect(ownerDownload.headers["content-type"]).toMatch(/application\/pdf/i);
    expect(ownerDownload.headers["content-disposition"]).toMatch(/attachment/i);

    // Grant the viewer read access.
    const grant = await owner
      .post(`/api/documents/${documentId}/permissions`)
      .send({
        userEmail: "viewer@trustvault.local",
        permission: "read",
      });
    expect(grant.status).toBe(201);

    // The viewer can download while the grant exists.
    const viewerDownload = await viewer.get(
      `/api/documents/${documentId}/download`
    );
    expect(viewerDownload.status).toBe(200);
    expect(viewerDownload.headers["content-type"]).toMatch(/application\/pdf/i);

    // Revoke the grant.
    const revoke = await owner.delete(
      `/api/documents/${documentId}/permissions/${viewerLogin.body.user.id}`
    );
    expect(revoke.status).toBe(200);

    // The viewer's next download must be denied.
    const deniedDownload = await viewer.get(
      `/api/documents/${documentId}/download`
    );
    expect(deniedDownload.status).toBe(404);
  } finally {
    if (documentId) {
      await pool.query(
        "DELETE FROM document_permissions WHERE document_id = $1",
        [documentId]
      );
      await pool.query("DELETE FROM documents WHERE id = $1", [documentId]);
    }

    if (storedFile && fs.existsSync(storedFile)) {
      fs.unlinkSync(storedFile);
    }
  }
},20000);


test("rejects a fake PDF with the wrong file signature", async () => {
  const owner = request.agent(app);

  const login = await owner.post("/api/auth/login").send({
    email: "owner@trustvault.local",
    password: process.env.SEED_OWNER_PASSWORD,
  });

  expect(login.status).toBe(200);

  const response = await owner
    .post("/api/documents/upload")
    .field("name", "Fake PDF")
    .field("category", "Testing")
    .attach(
      "document",
      Buffer.from("This is not a PDF"),
      {
        filename: "fake.pdf",
        contentType: "application/pdf",
      }
    );

  expect(response.status).toBe(400);
  expect(response.body.error).toMatch(/file contents/i);
});

test("rejects uploads larger than 5 MB", async () => {
  const owner = request.agent(app);

  const login = await owner.post("/api/auth/login").send({
    email: "owner@trustvault.local",
    password: process.env.SEED_OWNER_PASSWORD,
  });

  expect(login.status).toBe(200);

  const oversizedFile = Buffer.alloc(5 * 1024 * 1024 + 1, 65);
  oversizedFile.write("%PDF-", 0, "ascii");

  const response = await owner
    .post("/api/documents/upload")
    .field("name", "Oversized PDF")
    .field("category", "Testing")
    .attach("document", oversizedFile, {
      filename: "oversized.pdf",
      contentType: "application/pdf",
    });

  expect(response.status).toBe(400);
  expect(response.body.error).toMatch(/5 MB/i);
});
});

describe("Document edit and delete permissions", () => {
  let owner;
  let viewer;
  let viewerId;
  let testDocumentId;

  beforeAll(async () => {
    owner = request.agent(app);
    viewer = request.agent(app);

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
    viewerId = viewerLogin.body.user.id;

    const created = await owner.post("/api/documents").send({
      name: "Edit Delete Test Document",
      category: "Testing",
    });
    expect(created.status).toBe(201);
    testDocumentId = created.body.document.id;
  });

  afterAll(async () => {
    if (testDocumentId) {
      await pool.query(
        "DELETE FROM document_permissions WHERE document_id = $1",
        [testDocumentId]
      );
      await pool.query(
        "DELETE FROM documents WHERE id = $1 AND owner_id = $2",
        [testDocumentId, (await pool.query(
          "SELECT id FROM users WHERE email = $1",
          ["owner@trustvault.local"]
        )).rows[0].id]
      );
    }
  });

  test("owner can edit document metadata", async () => {
    const response = await owner
      .put(`/api/documents/${testDocumentId}`)
      .send({ name: "Updated Test Document", category: "Updated" });

    expect(response.status).toBe(200);
    expect(response.body.document.name).toBe("Updated Test Document");
    expect(response.body.document.category).toBe("Updated");
  });

  test("viewer with read permission cannot edit metadata", async () => {
    const grant = await owner
      .post(`/api/documents/${testDocumentId}/permissions`)
      .send({
        userEmail: "viewer@trustvault.local",
        permission: "read",
      });
    expect(grant.status).toBe(201);

    const response = await viewer
      .put(`/api/documents/${testDocumentId}`)
      .send({ name: "Unauthorized Edit", category: "Testing" });

    expect(response.status).toBe(404);
  });

  test("viewer with edit permission can edit metadata", async () => {
    const grant = await owner
      .post(`/api/documents/${testDocumentId}/permissions`)
      .send({
        userEmail: "viewer@trustvault.local",
        permission: "edit",
      });
    expect(grant.status).toBe(201);

    const response = await viewer
      .put(`/api/documents/${testDocumentId}`)
      .send({ name: "Viewer Edited Document", category: "Reviewed" });

    expect(response.status).toBe(200);
    expect(response.body.document.name).toBe("Viewer Edited Document");
  });

  test("viewer cannot delete a document, even with edit permission", async () => {
    const response = await viewer.delete(
      `/api/documents/${testDocumentId}`
    );

    expect(response.status).toBe(403);

    const stillExists = await pool.query(
      "SELECT id FROM documents WHERE id = $1",
      [testDocumentId]
    );
    expect(stillExists.rows).toHaveLength(1);
  });

  test("owner can delete a document", async () => {
    const created = await owner.post("/api/documents").send({
      name: "Owner Delete Test",
      category: "Testing",
    });
    expect(created.status).toBe(201);

    const id = created.body.document.id;
    const response = await owner.delete(`/api/documents/${id}`);
    expect(response.status).toBe(200);

    const remaining = await pool.query(
      "SELECT id FROM documents WHERE id = $1",
      [id]
    );
    expect(remaining.rows).toHaveLength(0);
  });
});
afterAll(async () => {
    await pool.end();
  });