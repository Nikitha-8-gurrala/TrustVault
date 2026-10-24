
import { useCallback, useEffect, useMemo, useState } from "react";
import "./App.css";

const API = import.meta.env.VITE_API_URL || "/api";

async function apiRequest(url, options = {}) {
  const response = await fetch(`${API}${url}`, {
    credentials: "include",
    ...options,
  });

  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json")
    ? await response.json()
    : null;

  if (!response.ok) {
    throw new Error(body?.error || `Request failed (${response.status})`);
  }

  return body;
}

function App() {
  const [user, setUser] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [auditIntegrity, setAuditIntegrity] = useState(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
const [error, setError] = useState("");
const [cooldownSeconds, setCooldownSeconds] = useState(0);
  const [notice, setNotice] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All categories");
  const [createdAfter, setCreatedAfter] = useState("");
const [createdBefore, setCreatedBefore] = useState("");
  const [showUpload, setShowUpload] = useState(false);
  const [uploadName, setUploadName] = useState("");
  const [uploadCategory, setUploadCategory] = useState("General");
  const [uploadFile, setUploadFile] = useState(null);
  const [permissionDoc, setPermissionDoc] = useState(null);
const [permissionEmail, setPermissionEmail] = useState("");
const [permissionLevel, setPermissionLevel] = useState("read");
const [documentPermissions, setDocumentPermissions] = useState([]);

  const loadDocuments = useCallback(async () => {
    const result = await apiRequest("/documents");
    setDocuments(result.documents || []);
  }, []);
  const loadDocumentPermissions = useCallback(async (docId) => {
  const result = await apiRequest(`/documents/${docId}/permissions`);
  setDocumentPermissions(result.permissions || []);
}, []);
    async function handleGrantPermission(event) {
    event.preventDefault();

    if (!permissionDoc) return;

    setError("");
    setNotice("");

    try {
      await apiRequest(`/documents/${permissionDoc.id}/permissions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userEmail: permissionEmail.trim(),
          permission: permissionLevel,
        }),
      });

      setNotice(`Access granted to ${permissionEmail.trim()}.`);
      await loadDocumentPermissions(permissionDoc.id);
      setPermissionEmail("");
    } catch (err) {
      setError(err.message);
    }
  }
  const loadAuditLogs = useCallback(async () => {
  setAuditLoading(true);
  try {
    const result = await apiRequest("/admin/audit-logs");
    setAuditEvents(result.events || []);
    setAuditIntegrity(result.integrity || null);
    console.log("Audit integrity verification:", result.integrity);
  } finally {
    setAuditLoading(false);
  }
}, []);

  const checkSession = useCallback(async () => {
    try {
      const result = await apiRequest("/auth/me");
      setUser(result.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkSession();
  }, [checkSession]);
  useEffect(() => {
  if (cooldownSeconds <= 0) return;

  const timer = setTimeout(() => {
    setCooldownSeconds((seconds) => Math.max(0, seconds - 1));
  }, 1000);

  return () => clearTimeout(timer);
}, [cooldownSeconds]);

    useEffect(() => {
    if (!user) return;

    const role = String(user.role || "").toLowerCase();

    if (role === "admin") {
      loadAuditLogs().catch((err) => setError(err.message));
    } else {
      loadDocuments().catch((err) => setError(err.message));
    }
  }, [user, loadDocuments, loadAuditLogs]);
  const categories = useMemo(
    () => [
      "All categories",
      ...new Set(documents.map((doc) => doc.category).filter(Boolean)),
    ],
    [documents]
  );

  const filteredDocuments = useMemo(() => {
  const query = search.trim().toLowerCase();

  return documents.filter((doc) => {
    const matchesCategory =
      category === "All categories" || doc.category === category;

    const matchesSearch =
      !query ||
      [doc.name, doc.category, doc.owner_email, doc.owner_name]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));

    const createdDate = doc.created_at
      ? new Date(doc.created_at).toISOString().slice(0, 10)
      : "";

    const matchesCreatedAfter =
      !createdAfter || (createdDate && createdDate >= createdAfter);

    const matchesCreatedBefore =
      !createdBefore || (createdDate && createdDate <= createdBefore);

    return (
      matchesCategory &&
      matchesSearch &&
      matchesCreatedAfter &&
      matchesCreatedBefore
    );
  });
}, [documents, search, category, createdAfter, createdBefore]);

  async function handleLogin(event) {
  event.preventDefault();

  if (cooldownSeconds > 0) return;

  setBusy(true);
  setError("");

  try {
    const result = await apiRequest("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    setUser(result.user);
    setPassword("");
    setNotice("Welcome to TrustVault.");
    setCooldownSeconds(0);
  } catch (err) {
    const match = err.message.match(/Try again in (\d+) seconds/i);

    if (match) {
      setCooldownSeconds(Number(match[1]));
    }

    setError(err.message);
  } finally {
    setBusy(false);
  }
}

  async function handleLogout() {
    setError("");
    try {
      await apiRequest("/auth/logout", { method: "POST" });
    } catch {
      // Clear the local screen even if the logout request fails.
    }
    setUser(null);
    setDocuments([]);
    setNotice("");
  }

  async function handleUpload(event) {
    event.preventDefault();
    if (!uploadFile) {
      setError("Choose a file to upload.");
      return;
    }

    const formData = new FormData();
    formData.append("name", uploadName || uploadFile.name);
    formData.append("category", uploadCategory);
    formData.append("document", uploadFile);

    setBusy(true);
    setError("");
    setNotice("");

    try {
      await apiRequest("/documents/upload", {
        method: "POST",
        body: formData,
      });

      await loadDocuments();
      setShowUpload(false);
      setUploadName("");
      setUploadCategory("General");
      setUploadFile(null);
      setNotice("Document uploaded successfully.");
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }
function handleRead(doc) {
  window.open(
    `${API}/documents/${doc.id}/download?inline=1`,
    "_blank",
    "noopener,noreferrer"
  );
}
  async function handleDownload(doc) {
    setError("");
    try {
      const response = await fetch(
        `${API}/documents/${doc.id}/download`,
        { credentials: "include" }
      );

      if (!response.ok) {
        const body = await response.json().catch(() => null);
        throw new Error(body?.error || `Download failed (${response.status})`);
      }

      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = objectUrl;
      link.download = doc.name || "document";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleEdit(doc) {
    const name = window.prompt("Document name:", doc.name);
    if (name === null) return;

    const categoryValue = window.prompt("Category:", doc.category || "General");
    if (categoryValue === null) return;

    setError("");
    try {
      await apiRequest(`/documents/${doc.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          category: categoryValue.trim(),
        }),
      });

      await loadDocuments();
      setNotice("Document details updated.");
    } catch (err) {
      setError(err.message);
    }
  }

  async function handleDelete(doc) {
    if (!window.confirm(`Delete "${doc.name}" permanently?`)) return;

    setError("");
    try {
      await apiRequest(`/documents/${doc.id}`, { method: "DELETE" });
      await loadDocuments();
      setNotice("Document deleted.");
    } catch (err) {
      setError(err.message);
    }
  }

  if (loading) {
    return <main className="loading-screen">Loading TrustVault…</main>;
  }

  if (!user) {
    return (
      <main className="login-page">
        <section className="login-card">
          <div className="brand-mark">T</div>
          <p className="eyebrow">SECURE DOCUMENT MANAGEMENT</p>
          <h1>Welcome to TrustVault</h1>
          <p className="muted">
            Your documents, protected by permissions you control.
          </p>

          {error && <div className="alert error">{error}</div>}

          <form className="login-form" onSubmit={handleLogin}>
            {cooldownSeconds > 0 && (
  <p role="status" aria-live="polite">
    Login temporarily locked. Try again in{" "}
    {Math.floor(cooldownSeconds / 60)}:
    {String(cooldownSeconds % 60).padStart(2, "0")}.
  </p>
)}
            <label htmlFor="email">Email address</label>
            <input
              id="email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="you@company.com"
              required
              disabled={busy || cooldownSeconds > 0}
            />

            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter your password"
              required
              disabled={busy || cooldownSeconds > 0}
            />

            <button
  type="submit"
  className="primary-button full-width"
  disabled={busy || cooldownSeconds > 0}
>
  {busy
    ? "Signing in…"
    : cooldownSeconds > 0
      ? `Try again in ${Math.floor(cooldownSeconds / 60)}:${String(
          cooldownSeconds % 60
        ).padStart(2, "0")}`
      : "Sign in securely"}
</button>
          </form>

          <p className="login-footnote">
            Access is verified by the TrustVault server.
          </p>
        </section>
      </main>
    );
  }

  const role = String(user.role || "user").toLowerCase();

    if (role === "admin") {
    return (
      <div className="app-shell">
        <aside className="sidebar">
          <a className="brand" href="#">
            <span className="brand-mark small">T</span>
            <span>TrustVault</span>
          </a>
          <p className="nav-heading">ADMINISTRATION</p>
          <div className="nav-link active">Audit Logs</div>
          <div className="sidebar-note">
            <span className="status-dot" />
            Audit integrity monitoring
          </div>
          <div className="sidebar-bottom">
            <div className="user-avatar">A</div>
            <div>
              <strong>{user.email}</strong>
              <p>Administrator</p>
            </div>
            <button
  className="secondary-button logout-button"
  onClick={handleLogout}
  type="button"
>
  Logout
</button>
          </div>
        </aside>

        <main className="main-content">
          <header className="topbar">
            <div>
              <p className="eyebrow">SECURITY OVERSIGHT</p>
              <h1>Audit Logs</h1>
              <p>Review recorded activity and audit-chain integrity.</p>
            </div>
            <button
              className="secondary-button"
              onClick={() => loadAuditLogs().catch((err) => setError(err.message))}
            >
              Refresh
            </button>
          </header>

          {error && <div className="error-banner">{error}</div>}

          <section className="stats-grid">
            <article className="stat-card">
              <span>Audit entries loaded</span>
              <strong>{auditEvents.length}</strong>
            </article>
            <article className="stat-card">
              <span>Audit-chain integrity</span>
              <strong>{auditIntegrity?.valid === true ? "Valid" : auditIntegrity?.valid === false ? "Invalid" : "Unknown"}</strong>
            </article>
          </section>

          {auditIntegrity?.valid === false && (
            <div className="error-banner">
              Audit-chain verification failed. Review the integrity details.
            </div>
          )}

          <section className="documents-panel">
            <h2>Recent activity</h2>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Actor</th>
                    <th>Action</th>
                    <th>Outcome</th>
                    <th>Document ID</th>
                  </tr>
                </thead>
                <tbody>
                  {auditEvents.map((log) => (
                    <tr key={log.id}>
                      <td>{log.created_at ? new Date(log.created_at).toLocaleString() : "—"}</td>
                      <td>{log.actor_email || "System"}</td>
                      <td>{log.action}</td>
                      <td>
  <span className={`audit-outcome ${log.outcome === "denied" ? "denied" : "success"}`}>
    {log.outcome}
  </span>
</td>
                      <td>{log.document_id || "—"}</td>
                    </tr>
                  ))}
                  {auditEvents.length === 0 && (
                    <tr>
                      <td colSpan={5}>No audit events loaded.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      </div>
    );
  }
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#" aria-label="TrustVault home">
          <span className="brand-mark small">T</span>
          <span>TrustVault</span>
        </a>

        <p className="nav-heading">WORKSPACE</p>
        <div className="nav-link active">
          <span>▦</span> Documents
        </div>
        <div className="sidebar-note">
          <span className="status-dot" />
          Secure workspace
        </div>

        <div className="sidebar-bottom">
          <div className="avatar">
            {(user.email || "U").slice(0, 1).toUpperCase()}
          </div>
          <div className="account-info">
            <strong>{user.email}</strong>
            <span>{role}</span>
          </div>
          <button
  className="secondary-button logout-button"
  onClick={handleLogout}
  type="button"
>
  Logout
</button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace / Documents</span>
            <h1>Documents</h1>
            <p className="muted">
              Manage files and control access from one secure place.
            </p>
          </div>
          <div className="topbar-user">
            <span className="status-dot" />
            Signed in as <strong>{role}</strong>
          </div>
        </header>

        {error && (
          <div className="alert error" role="alert">
            {error}
            <button onClick={() => setError("")} aria-label="Dismiss error">
              ×
            </button>
          </div>
        )}

        {notice && (
          <div className="alert success" role="status">
            {notice}
            <button onClick={() => setNotice("")} aria-label="Dismiss message">
              ×
            </button>
          </div>
        )}

        <section className="welcome-banner">
          <div>
            <p className="eyebrow">YOUR SECURE WORKSPACE</p>
            <h2>Your files. Your control.</h2>
            <p>
              Documents are accessible according to server-enforced permissions.
            </p>
          </div>
          <div className="banner-symbol" aria-hidden="true">◇</div>
        </section>

        <section className="stats-grid">
          <article className="stat-card">
            <span className="stat-label">Accessible documents</span>
            <strong>{documents.length}</strong>
            <span className="stat-caption">Files available to your account</span>
          </article>
          <article className="stat-card">
            <span className="stat-label">Categories</span>
            <strong>{Math.max(0, categories.length - 1)}</strong>
            <span className="stat-caption">Across your document library</span>
          </article>
          <article className="stat-card">
            <span className="stat-label">Account role</span>
            <strong className="role-value">{role}</strong>
            <span className="stat-caption">Determines available actions</span>
          </article>
        </section>

        <section className="documents-section">
          <div className="section-heading">
            <div>
              <h2>Document library</h2>
              <p className="muted">
                {filteredDocuments.length} document
                {filteredDocuments.length === 1 ? "" : "s"} shown
              </p>
            </div>
            {role === "owner" && (
              <button
                className="primary-button"
                onClick={() => setShowUpload((value) => !value)}
              >
                + Upload document
              </button>
            )}
          </div>

          {showUpload && role === "owner" && (
            <form className="upload-panel" onSubmit={handleUpload}>
              <div>
                <h3>Upload a document</h3>
                <p className="muted">PDF uploads are validated by the server.</p>
              </div>
              <label>
                Document name
                <input
                  value={uploadName}
                  onChange={(event) => setUploadName(event.target.value)}
                  placeholder="Quarterly report"
                />
              </label>
              <label>
                Category
                <input
                  value={uploadCategory}
                  onChange={(event) => setUploadCategory(event.target.value)}
                  required
                />
              </label>
              <label>
                Select file
                <input
                  type="file"
                  accept=".pdf,application/pdf"
                  onChange={(event) =>
                    setUploadFile(event.target.files?.[0] || null)
                  }
                  required
                />
              </label>
              <div className="form-actions">
                <button
                  className="secondary-button"
                  type="button"
                  onClick={() => setShowUpload(false)}
                >
                  Cancel
                </button>
                <button className="primary-button" disabled={busy}>
                  {busy ? "Uploading…" : "Upload file"}
                </button>
              </div>
            </form>
          )}
                    {permissionDoc && role === "owner" && (
            <form
              className="upload-panel"
              onSubmit={handleGrantPermission}
            >
              <h3>Manage access: {permissionDoc.name}</h3>
              <div>
  <h4>People with access</h4>
  {documentPermissions.length === 0 ? (
    <p className="muted">No access grants found.</p>
  ) : (
    documentPermissions.map((permission) => (
      <div key={permission.user_id}>
        <span>{permission.email}</span>
        {" — "}
        <span>{permission.permission}</span>
        <button
  type="button"
  onClick={async () => {
    try {
      await apiRequest(
        `/documents/${permissionDoc.id}/permissions/${permission.user_id}`,
        { method: "DELETE" }
      );
      await loadDocumentPermissions(permissionDoc.id);
      setNotice(`Access revoked for ${permission.email}.`);
      setError("");
    } catch (err) {
      setError(err.message);
    }
  }}
>
  Revoke
</button>
      </div>
    ))
  )}
</div>
              <label>
                Recipient email
                <input
                  type="email"
                  value={permissionEmail}
                  onChange={(event) => setPermissionEmail(event.target.value)}
                  placeholder="user@example.com"
                  required
                />
              </label>

              <label>
                Permission level
                <select
                  value={permissionLevel}
                  onChange={(event) => setPermissionLevel(event.target.value)}
                >
                  <option value="read">Read only</option>
                  <option value="edit">Read and edit</option>
                </select>
              </label>

              <div className="form-actions">
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setPermissionDoc(null)}
                >
                  Cancel
                </button>
                <button type="submit" className="primary-button">
                  Grant access
                </button>
              </div>
            </form>
          )}
          <div className="filters">
            <div className="search-box">
              <span>⌕</span>
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search documents by name or category…"
                aria-label="Search documents"
              />
            </div>
            <select
              value={category}
              onChange={(event) => setCategory(event.target.value)}
              aria-label="Filter by category"
            >
              {categories.map((item) => (
                <option key={item} value={item}>{item}</option>
              ))}
            </select>
            <label>
  Created after
  <input
    type="date"
    value={createdAfter}
    onChange={(event) => setCreatedAfter(event.target.value)}
    aria-label="Filter documents created on or after this date"
  />
</label>

<label>
  Created before
  <input
    type="date"
    value={createdBefore}
    onChange={(event) => setCreatedBefore(event.target.value)}
    aria-label="Filter documents created on or before this date"
  />
</label>
            <button
              className="secondary-button"
              onClick={() => loadDocuments().catch((err) => setError(err.message))}
            >
              {auditLoading ? "Refreshing…" : "Refresh"}
            </button>
          </div>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DOCUMENT</th>
                  <th>CATEGORY</th>
                  <th>CREATED</th>
                  <th className="actions-heading">ACTIONS</th>
                </tr>
              </thead>
              <tbody>
                {filteredDocuments.map((doc) => (
                  <tr key={doc.id}>
                    <td>
                      <div className="document-cell">
                        <span className="file-icon">PDF</span>
                        <div>
                          <strong>{doc.name}</strong>
                          <span className="document-subtitle">
                            {doc.owner_email || doc.owner_name || "TrustVault document"}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td><span className="category-pill">{doc.category || "General"}</span></td>
                    <td>{doc.created_at ? new Date(doc.created_at).toLocaleDateString() : "—"}</td>
                    <td>
                      <div className="row-actions">
  <button
    type="button"
    onClick={() => handleRead(doc)}
    title="Read document"
  >
    Read
  </button>

  {(role === "owner" || doc.access_level === "edit") && (
    <button
      type="button"
      onClick={() => handleEdit(doc)}
      title="Edit metadata"
    >
      Edit
    </button>
  )}

  <button
    type="button"
    onClick={() => handleDownload(doc)}
    title="Download"
  >
    Download
  </button>

  {role === "owner" && (
    <>
      <button
        type="button"
        onClick={() => {
          setPermissionDoc(doc);
          setPermissionEmail("");
          setPermissionLevel("read");
          setDocumentPermissions([]);
          setError("");
          setNotice("");
          loadDocumentPermissions(doc.id).catch((err) =>
            setError(err.message)
          );
        }}
      >
        Manage Access
      </button>

      <button
        type="button"
        className="danger-action"
        onClick={() => handleDelete(doc)}
        title="Delete document"
      >
        Delete
      </button>
    </>
  )}
</div>
                    </td>
                  </tr>
                ))}
                {filteredDocuments.length === 0 && (
                  <tr>
                    <td colSpan="4">
                      <div className="empty-state">
                        <div className="empty-icon">▤</div>
                        <strong>No documents found</strong>
                        <p>
                          {documents.length
                            ? "Try a different search or category."
                            : "Documents you can access will appear here."}
                        </p>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <p className="security-footnote">
            <span className="status-dot" />
            Access checks are enforced by the server, not just this interface.
          </p>
        </section>

        <footer className="page-footer">
          <span>TrustVault · Secure document management</span>
          <span>Access controlled · Audit monitored</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
