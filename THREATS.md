# TrustVault — Threat Model

**Last updated:** 24 October 2026

## 1. What is this file about?

TrustVault is a document-sharing application. The main goal is to make sure that only the right people can access a document.

While building it, I thought about what could go wrong, how I could prevent it, and what still needs improvement. This file explains those decisions honestly.

## 2. Who can do what?

- **Admin:** Can view audit logs and check whether the audit records are intact.
- **Owner:** Can upload and manage their own documents and share them with other users.
- **Viewer:** Can read or download documents shared with them.
- **Edit access:** A user with edit permission can also edit a shared document.

The backend checks permissions. Hiding a button in the frontend is not enough because someone could still try to call the API directly.

## 3. What could go wrong?

### Someone accesses another user's document

A user might try changing a document ID in the URL to access someone else's file.

**What I did:** Added backend checks so that document access depends on ownership or the permission granted to the user.

**What still needs testing:** I need to test all the unauthorized access cases against the final deployed version.

### Someone keeps access after it is revoked

A user might try opening a document even after the owner removes their permission.

**What I did:** Added a permission-revocation route and backend permission checks.

**What still needs testing:** I need to confirm that access stops immediately on the next request after revocation.

### A viewer tries to edit or delete a document

A viewer should not be able to make changes or delete another person's document.

**What I did:** Editing requires ownership or edit permission, while deletion is restricted to the owner.

### Someone tries to become an admin

A user might try changing their role or granting themselves extra permissions.

**What I did:** The backend checks the logged-in user's role and validates permission changes.

**What still needs testing:** I need to check more cases where users try to change roles or access other owners' documents.

### Someone uploads a bad file

A user might upload an oversized file or a file pretending to be an allowed type.

**What I did:** Added file size, file type, and file signature checks.

**What is missing:** I have not added malware scanning, so these checks cannot guarantee that every uploaded file is safe.

### Someone repeatedly guesses passwords

An attacker might keep trying different passwords.

**What I did:** Added failed-login tracking and a temporary cooldown after repeated failures.

**What I tested:** Five incorrect login attempts returned HTTP 401, and the next attempt returned HTTP 429.

**What still needs testing:** Cooldown expiry and some other login edge cases need more tests. A cooldown can also be misused to temporarily block a genuine user.

### Someone changes the audit logs

An attacker might try changing or removing records to hide what happened.

**What I did:** Added audit logging and a hash chain that helps detect changes to the recorded entries.

**What I tested:** The backend test suite passed 35 tests across two test suites.

**What is still a risk:** Someone with enough database access might rewrite the records and calculate new hashes. The hash chain helps detect tampering, but it cannot prevent every possible attack.

### Someone tries to access files through a manipulated path

An attacker might use a specially crafted filename to access files they should not reach.

**What I did:** Uploaded files use server-generated identifiers rather than relying on the original filename.

### Someone steals a secret

Database credentials or session secrets could cause serious problems if they are exposed.

**What I did:** Local environment files are excluded from Git, and production secrets are configured through Render environment variables.

**What I still need to do:** Review the repository carefully before the final submission to make sure no secrets have been committed.

### Uploaded files disappear

Files stored on a hosting service's temporary filesystem may disappear after a restart or redeployment.

**What I did:** I deployed the backend and investigated options for storing files more reliably.

**What is still missing:** Durable file storage is not yet integrated. I considered Cloudflare R2 but did not activate it because I did not want to make a billing commitment for this project.

## 4. What does the admin see?

The admin can view recent audit activity and check the integrity of the audit chain.

The audit trail is intended to record important actions such as uploads, downloads, edits, deletions, permission changes, and relevant security events.

I still need to verify that all these events are recorded correctly in the final deployed version.

## 5. Where AI fits into this project

AI helped me understand the requirements, plan the security controls, and work through implementation problems.

If I add AI-based suggestions for sharing documents in the future, AI must never grant access on its own. The owner must make the final decision, and that decision should be recorded in the audit log.

This suggestion feature is not currently implemented.

## 6. What is working, and what remains?

**Completed or checked:**

- Backend automated tests passed: 35 tests across two suites.
- Frontend production build completed successfully.
- Manual testing confirmed the failed-login threshold behavior.
- The deployed backend health endpoint responded successfully.
- Document permission and audit functionality have been added to the local code.

**Still to do:**

- Test unauthorized access, editing, and deletion against the final deployment.
- Confirm that revoking access blocks the next request.
- Test audit records and audit-chain tampering detection.
- Test login cooldown expiry.
- Deploy and test the frontend.
- Add durable file storage.
- Verify that the deployed version contains the latest code.

## 7. Current limitation

The backend is deployed, but that does not mean every feature has been tested in production. The deployed version may not contain my latest local changes.

I have focused first on authentication, document permissions, and audit logging. Some features, including durable file storage and full production security testing, are still unfinished.

I will keep these limitations clear rather than claiming that the application is completely secure.
