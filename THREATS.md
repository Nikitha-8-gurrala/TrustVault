# TrustVault — Threat Model

Status: Initial assessment; authentication foundation implemented and locally tested. Document-security controls remain pending.  
Last updated: 2026-10-21

## 1. Purpose

TrustVault is a document storage and sharing application. This document identifies potential security threats, planned controls, verification results, and remaining limitations.

A control is considered verified only to the extent supported by actual implementation and test evidence. Local testing does not establish production security.

## 2. Roles and intended permissions

- **Admin:** Intended to manage users and review activity, but must not read document contents.
- **Owner:** Intended to manage their own documents and grant or revoke access.
- **Viewer:** Intended to read or download documents only when explicitly authorized.

**Current status:** The database contains seeded accounts for all three roles. The login endpoint returns the role from the database. Full role-based authorization and document-level permission enforcement are not implemented yet.

## 3. Threats and mitigations

### Threat 1: Unauthorized document access

- **Risk:** A user changes a document ID to access another user's document.
- **Planned mitigation:** Check ownership and permissions on every protected document request.
- **Verification:** Pending; document endpoints and authorization checks are not implemented.

### Threat 2: Access after revocation

- **Risk:** A user continues accessing a document after permission is revoked.
- **Planned mitigation:** Check current permissions on every protected request.
- **Verification:** Pending; document grants and revocation are not implemented.

### Threat 3: Unauthorized editing or deletion

- **Risk:** A viewer attempts to edit or delete a document.
- **Planned mitigation:** Enforce server-side read, edit, and delete permissions.
- **Verification:** Pending.

### Threat 4: Privilege escalation

- **Risk:** A user attempts to grant themselves administrator privileges.
- **Planned mitigation:** Use trusted server-side role records instead of roles submitted by clients.
- **Current control:** The current-user endpoint retrieves the role from PostgreSQL using the user ID stored in the session.
- **Verification:** The endpoint returned the seeded viewer's database role during local testing. Attempts to alter roles and full role-specific authorization remain untested.

### Threat 5: Malicious or oversized uploads

- **Risk:** An attacker uploads a disallowed, misleading, or oversized file.
- **Planned mitigation:** Enforce upload limits and validate file types and content.
- **Verification:** Pending; upload functionality is not implemented.

### Threat 6: Brute-force login attempts

- **Risk:** An attacker repeatedly attempts to guess account passwords.
- **Planned mitigation:** Hash passwords securely and apply login rate limiting.
- **Current control:** Seeded account passwords are stored as bcrypt hashes, and login verifies submitted passwords with bcrypt.
- **Verification:** A seeded viewer login succeeded locally. Invalid-credential behavior and rate limiting still require dedicated tests.
- **Remaining work:** Login rate limiting and automated tests for repeated failed attempts are not implemented.

### Threat 7: Audit-log tampering

- **Risk:** A user attempts to modify or delete audit records.
- **Planned mitigation:** Restrict audit-log operations through trusted server code and database permissions; evaluate tamper-evident integrity controls.
- **Verification:** Pending; the audit trail is not implemented.

### Threat 8: Path traversal

- **Risk:** A malicious filename attempts to access files outside the intended storage location.
- **Planned mitigation:** Use server-generated storage identifiers and validate filenames.
- **Verification:** Pending; file storage is not implemented.

### Threat 9: Missing records of denied access

- **Risk:** Unauthorized access attempts are not recorded.
- **Planned mitigation:** Record relevant authorization denials without logging secrets.
- **Verification:** Pending; security-event auditing is not implemented.

### Threat 10: Exposed secrets

- **Risk:** Passwords, tokens, or other secrets appear in source code or logs.
- **Planned mitigation:** Keep secrets in environment variables, exclude local environment files from version control, and avoid logging sensitive values.
- **Current control:** A root `.env` file is used for local configuration and is listed in `.gitignore`.
- **Verification:** The ignore rule was checked locally. A complete tracked-file and repository history review is still required before publishing.

## 4. Authentication verification

The following behavior has been observed during local development:

- A seeded viewer successfully logged in using the login endpoint.
- The protected `/api/auth/me` endpoint returned the viewer's database-backed identity and role when an authenticated session was supplied.
- A request without an authenticated session was rejected with an authentication-required response.
- The logout endpoint returned a successful response.
- A subsequent request using the previous session was rejected.

These are manual local tests, not automated regression tests. They do not establish that every authentication edge case is secure or that document authorization is enforced.

## 5. Planned audit trail

The intended audit trail will record security-relevant events, including document uploads, downloads, edits, deletions, permission changes, and denied access attempts.

Events should include relevant actor, action, target, timestamp, and outcome information while avoiding passwords, session tokens, and document contents.

Protection against alteration or deletion must be demonstrated through implementation and tests. A hash chain alone would not prevent a privileged actor from rewriting the entire chain; the final design must document its trust assumptions and limitations.

**Current status:** Audit logging and tamper-evident integrity controls are not implemented.

## 6. Verification checklist

- [x] Local login with a seeded viewer account succeeds.
- [x] The current-user endpoint returns database-backed identity and role for an authenticated session.
- [x] An unauthenticated request to the current-user endpoint is rejected.
- [x] Logout succeeds and the previous session is rejected on a subsequent request.
- [ ] Invalid credentials are tested with dedicated repeatable tests.
- [ ] Protected endpoints enforce the intended role policy.
- [ ] Unauthorized users cannot read or download documents.
- [ ] Unauthorized users cannot edit or delete documents.
- [ ] Revoked access is denied on subsequent requests.
- [ ] Role escalation attempts are rejected.
- [ ] Invalid and oversized uploads are rejected.
- [ ] Denied access attempts are recorded.
- [ ] Ordinary users cannot modify or delete audit history.
- [ ] Automated tests cover authorization failures and cross-user isolation.
- [ ] Critical security checks pass on the deployed application.



## 7. Known limitations

This is a working threat assessment, not a security certification. Current verification is limited to manual local tests of the authentication foundation. Document permissions, file handling, role-specific access controls, automated tests, deployment security, and the audit trail remain to be implemented and verified.

Protection against a compromised server or privileged database administrator may require additional controls beyond application-level restrictions.