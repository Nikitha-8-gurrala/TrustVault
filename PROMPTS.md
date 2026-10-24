# TrustVault — AI Development Log

## Why I am keeping this file

I used AI tools while building TrustVault, but I did not blindly accept every suggestion. This file records what I asked, what I learned, what needed improvement, and how I checked my work.

---

## 2026-10-19 — Understanding the problem statement

**AI tools:** Claude and ChatGPT.

**What I asked:** I shared the challenge instructions and asked for help understanding the requirements, choosing a technology stack, and planning the work step by step.

**What the tool suggested:** It explained the main security goals, proposed a Node.js/Express backend with PostgreSQL and React, and suggested working in small phases.

**What I learned:** I understood why document permissions, access revocation, and audit logs are important.

**What I did:** I collected the requirements and created the initial README.

**How I checked it:** I pushed the initial README commit to GitHub. No application security features had been tested at that stage.

**Commit link:** Add the real link to the initial README commit.

---

## 2026-10-21 — Building login and sessions

**AI tool:** ChatGPT.

**What I asked:** I asked for step-by-step help with login, checking the logged-in user, logout, and session authentication.

**What the tool suggested:** It explained bcrypt password checking, storing the user ID in the session, and using backend middleware to check authentication.

**What needed improvement:** My first request to the current-user endpoint returned HTTP 401 because I was not using the correct authenticated session.

**What I did:** I logged in again with the correct session and repeated the request.

**How I checked it:** I tested login, the current-user endpoint, rejection of an unauthenticated request, and rejection of the old session after logout.

**What was still missing then:** Document permissions, audit logging, and login protection were not yet complete at that stage.

**Commit link:** Add the real link to the authentication commit.

---

## 2026-10-24 — Adding document permissions and audit logs

**AI tool:** ChatGPT.

**What I asked:** I asked for help making sure users could only access documents they were allowed to see, and for guidance on recording important actions.

**What the tool suggested:** It helped me work through owner checks, read/edit permissions, permission revocation, and audit-chain verification.

**What I had to think about:** Hiding buttons in the frontend is not enough. A user could call the backend directly. Also, a hash chain helps detect changes, but it cannot stop every attack by someone with full database access.

**What I did:** I added backend permission checks, permission routes, audit logging, and hash-chain verification.

**How I checked it:** The backend test suite passed 35 tests across two suites. I also built the frontend successfully.

**What remains:** I still need to verify every important cross-user access case against the final deployed version.

**Commit link:** Add the real link after the changes are reviewed and committed.

---

## 2026-10-24 — Adding protection against repeated login failures

**AI tool:** ChatGPT.

**What I asked:** I asked how to detect repeated failed logins and temporarily stop further attempts.

**What the tool suggested:** It helped me implement a database-backed counter and a temporary cooldown.

**What I had to consider:** Blocking repeated attempts helps against password guessing, but an attacker might also use the cooldown to disrupt a genuine user's access.

**What I did:** I added failed-login tracking, a threshold of five attempts, a ten-minute tracking window, and a temporary cooldown.

**How I checked it:** Five incorrect attempts returned HTTP 401, and the next attempt returned HTTP 429.

**What remains:** I still need to test cooldown expiry and other edge cases.

**Commit link:** Add the real link after the changes are reviewed and committed.

---

## 2026-10-24 — Deploying the backend

**AI tool:** ChatGPT.

**What I asked:** I asked for help deploying the backend to Render while keeping my GitHub repository private.

**What the tool suggested:** It explained how to configure the backend service, add environment variables, and check the health endpoint.

**What I had to consider:** A successful health check only tells me that the service is responding. It does not prove that all security features work in production.

**What I did:** I deployed the backend and checked its health endpoint.

**How I checked it:** The deployed backend returned a successful health response.

**What remains:** The deployment used commit `825ac3f`. My later local changes still need to be committed and deployed before I can claim they are live.

**Commit link:** Add the actual deployment commit link.

---

## 2026-10-24 — Considering file storage

**AI tool:** ChatGPT.

**What I asked:** I asked how to keep uploaded files from disappearing after a hosting restart or redeployment.

**What the tool suggested:** It explained that temporary local storage is not reliable for long-term files and suggested external object storage.

**What I had to consider:** Installing a storage SDK does not mean the application is actually using that storage. I also did not want to activate a service that required a billing commitment.

**What I did:** I investigated Cloudflare R2 but did not activate it. The application still uses local file storage.

**How I checked it:** The backend was deployed, but durable storage has not been integrated or verified.

**What remains:** I need to choose and test a suitable durable storage solution, or clearly explain this limitation in the final submission.

**Commit link:** Add the actual commit link if and when the storage changes are committed.

---

## My approach to using AI

AI helped me understand unfamiliar concepts and work through implementation problems. I still needed to run tests, inspect the code, and make decisions about what to implement.

I will use actual commit links and describe only results I have verified. If a feature is unfinished, I will say so rather than claim it works.
