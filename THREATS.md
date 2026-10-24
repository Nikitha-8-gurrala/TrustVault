TrustVault — Threat Model
Last updated: 24 October 2026
1. What is this file about?
TrustVault is a document-sharing application. Its main goal is to make sure that only the right people can access a document.

During development, I considered what could go wrong, which controls could reduce those risks, and what still needs improvement. This file explains those decisions and the current limitations honestly.
2. Who can do what?
- Admin: Can view audit logs and check whether the audit records are intact.
- Owner: Can upload and manage their own documents and share them with other users.
- Viewer: Can read or download documents shared with them.
- Edit access: A user with edit permission can also edit a shared document.
The backend checks permissions. Hiding a button in the frontend is not enough because someone could still try to call the API directly.
3. What could go wrong?
Someone accesses another user's document
A user might try changing a document ID in the URL to access someone else's file.

What I did: Added backend checks so document access depends on ownership or permissions granted to the user.

What still needs testing: Test unauthorized-access cases against the final deployed version, including direct API requests.
Someone keeps access after it is revoked
A user might try opening a document even after the owner removes their permission.

What I did: Added a permission-revocation route and backend permission checks.

What still needs testing: Confirm that access is denied on the next request after revocation.
A viewer tries to edit or delete a document
A viewer should not be able to change or delete another person's document.

What I did: Editing requires ownership or edit permission, while deletion is restricted to the owner.

What still needs testing: Verify unauthorized edit and delete attempts against the deployed application.
Someone tries to become an admin
A user might try changing their role or granting themselves extra permissions.

What I did: The backend checks the logged-in user's role and validates permission changes.

What still needs testing: Test attempts to change roles or access documents belonging to other owners.
Someone uploads a bad file
A user might upload an oversized file or a file pretending to be an allowed type.

What I did: Added file-size, file-type, and file-signature checks.

What is missing: Malware scanning has not been added, so these checks cannot guarantee that every uploaded file is safe.

What still needs testing: Verify upload validation against the final deployed version.
Someone repeatedly guesses passwords
An attacker might keep trying different passwords.

What I did: Added failed-login tracking and a temporary cooldown after repeated failures.

What I tested: Five incorrect login attempts returned HTTP 401, and the next attempt returned HTTP 429 in the tested environment.

What still needs testing: Test cooldown expiry and other login edge cases. A cooldown can also be misused to temporarily block a genuine user.
Someone changes the audit logs
An attacker might try changing or removing records to hide what happened.

What I did: Added audit logging and a hash chain intended to help detect changes to recorded entries.

What I tested: The backend test suite passed 35 tests across two test suites.

What is still a risk: The overall test count does not by itself prove that every audit-tampering scenario is covered. Someone with sufficient database access might rewrite records and recalculate hashes. The hash chain helps detect tampering but cannot prevent every possible attack.

What still needs testing: Verify representative audit events and run a specific audit-chain tampering test against the final deployed version.
Someone tries to access files through a manipulated path
An attacker might use a specially crafted filename to access files they should not reach.

What I did: Uploaded files use server-generated identifiers rather than relying on the original filename.

What still needs testing: Verify path-handling protections against relevant malicious inputs.
Someone steals a secret
Database credentials or session secrets could cause serious problems if exposed.

What I did: Local environment files are excluded from Git, and production secrets are configured through Render environment variables.

What I still need to do: Review the current repository and its history to check that no secrets were committed. Excluding environment files now does not remove secrets that may have been committed previously.
Uploaded files disappear
Files stored on a hosting service's local filesystem may be lost during redeployment or other filesystem replacement events.

What I did: Deployed the backend and investigated options for storing files more reliably.

What is still missing: Durable file storage is not integrated. I considered Cloudflare R2 but did not activate it because I did not want to make a billing commitment for this project. Uploaded-file persistence across redeployments has therefore not been established.
4. What does the admin see?
The admin can view recent audit activity and check the integrity of the audit chain.

The audit trail is intended to record important actions such as uploads, downloads, edits, deletions, permission changes, and relevant security events.

What still needs testing: Verify that these representative events are recorded correctly and that the integrity check behaves as expected in the final deployed version.
5. Where AI fits into this project
AI helped me understand the requirements, plan security controls, and work through implementation problems.

If AI-based sharing suggestions are added in the future, AI must never grant access on its own. The owner must make the final decision, and that decision should be recorded in the audit log.

This suggestion feature is not currently implemented.
6. What is working, and what remains?
Completed or checked
- Backend automated test suite passed: 35 tests across two test suites.
- Frontend production build completed successfully.
- Failed-login threshold behavior was tested: five incorrect attempts returned HTTP 401, followed by HTTP 429.
- The deployed backend health endpoint responded successfully.
- The frontend and backend have been deployed.
- After the session-cookie configuration change, live login and document listing worked.
- A new test file was uploaded and downloaded successfully in the live application.
- Document permission and audit functionality have been added to the code. Full production security verification is still outstanding.
Still to do
- Verify that the final deployed commit matches the submitted repository.
- Test unauthorized document access and direct API requests against the deployed application.
- Verify unauthorized edit and delete attempts.
- Capture evidence that revocation blocks the next direct request.
- Verify representative audit events and audit-chain tampering detection on the deployed version.
- Test upload validation and cooldown expiry on the deployed version.
- Review current files and repository history for secrets.
- Integrate and verify durable file storage, including persistence across redeployments.
- Test relevant path-manipulation cases against the deployed version.
7. Current limitations
The backend and frontend are deployed, and basic live login and test-file upload/download have been checked. However, I still need to verify that the final deployed commit matches the submitted repository and complete the remaining production security tests.

Durable file storage is not integrated, so uploaded-file persistence across redeployments is not guaranteed. Some security controls have been implemented but have not all been independently verified against the deployed application.

I will report these limitations clearly rather than claiming that the application is completely secure.