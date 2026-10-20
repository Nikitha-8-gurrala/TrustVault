# TrustVault — AI Development Log

## Purpose

This file records how AI tools are used during TrustVault development, including useful suggestions, mistakes discovered, corrections made, and verification results.


### 2026-10-19 — Understanding the TrustVault problem statement

AI tools: Claude (free plan) and ChatGPT.
Context:I uploaded 11 screenshots containing the hackathon problem statement and instructions to Claude.

Prompt: “Go through the problem statement clearly and act as a developer. Remember that I don't see the best visual output but working and functionality. I have to push and make commits to GitHub regularly over the coming five days until the deadline, not all at once on the last day. I should be able to explain it to them later on, so explain the problem statement once, what solution we are offering, and the features or things to know about our product. How are we achieving it, in which order would we like to develop and deploy it, and how can we follow an agile, phase-wise approach?”

Output: Claude explained the problem statement and highlighted three essential security requirements: only authorized users should access documents, security-relevant activities should be auditable, and revoked access should stop working immediately. It proposed a technology stack using Node.js/Express, PostgreSQL, and React; three user roles; document-specific permissions; a hash-chained audit-log design; a threat-model outline; and a phased development plan with regular deployments.

What I learned: I understood the main security goals, the proposed architecture, the importance of server-side authorization, and why development should proceed in small, verifiable phases.

Work completed: I gathered the project requirements and created the initial README file in the GitHub repository.

Verification: The initial README commit was pushed to GitHub successfully. No application features or security controls had been implemented or tested at this stage.

Commit: `Initial commit` — README file. Add the actual GitHub commit link when available.

---

---
### 2026-10-21 — Implementing and manually checking session authentication

AI tool: ChatGPT.

Context: I was building the Express backend and connecting it to PostgreSQL. The seeded test accounts represent the admin, owner, and viewer roles.

Prompt summary: I asked for step-by-step help implementing login, checking the currently authenticated user, logout, and session-based authentication, with explanations so I could understand and test the code myself.

Output: The guidance covered password-hash verification with bcrypt, regenerating the session after successful login, storing the user's ID in the session, middleware that checks the session against the users table, a current-user endpoint, and logout that destroys the session.

Work completed: Implemented the login endpoint, authentication middleware, /api/auth/me, and /api/auth/logout in the Express backend.

Verification: Manual local checks succeeded for viewer login, retrieving the authenticated user's details, rejecting an unauthenticated request to /api/auth/me with HTTP 401, and rejecting access using the old session after logout. These were manual checks, not automated tests.

Limitations: Document-level permissions, authorization for document operations, audit logging, automated authentication tests, login rate limiting, and production cookie settings are not yet complete.

Correction or issue: During manual testing, an initial request to /api/auth/me returned HTTP 401 because the session used for the request was not the authenticated session. Logging in again with the correct session and repeating the request verified the expected behavior.

Commit: Add the actual commit hash and link after the authentication changes and related documentation are committed.

