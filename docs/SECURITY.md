# PhishNetra — Security & Zero-Trust Policy (Milestone 1)

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Milestone:** 1

---

## 1. Zero-Trust Security Principles

1. **Never Trust Candidate Input:** All submitted URLs, query strings, and authentication payloads are untrusted and rigorously validated via Zod schemas and Pydantic models before processing.
2. **Defensive Isolation:** The Python ML execution environment is completely separated from the Node.js API application layer.
3. **No Unauthenticated Execution:** Critical analytical workflows and historical audits require verified JWT Bearer tokens.

---

## 2. Server-Side Request Forgery (SSRF) Defense Architecture

A core vulnerability in phishing detection engines is **Server-Side Request Forgery (SSRF)**, where a malicious URL tricks the backend server into fetching internal microservices, loopback adapters (`http://127.0.0.1`, `http://localhost`), link-local IPs, or cloud metadata endpoints (`http://169.254.169.254`).

### Milestone 1 Deliberate Policy:
- In Milestone 1, **the backend server never initiates an outbound HTTP/TCP request to the user-submitted URL**.
- All feature extraction operates exclusively on lexical, syntactic, and structural token parsing in memory.
- In Milestone 3, live DOM fetching and screenshotting will be implemented inside a dedicated, network-isolated worker container with non-routable interfaces, private IP blacklisting, DNS-pinning, and strict egress firewalls.

---

## 3. Authentication & Credential Security

- **Password Hashing:** Implemented with `bcryptjs` using 10 salt rounds. Plaintext passwords are never logged, persisted, or returned in API responses.
- **Session Tokens:** Stateless JSON Web Tokens (JWT) signed with HMAC-SHA256 and configurable expiration (`JWT_EXPIRES_IN=7d`).
- **Cookie Flags:** Cookies are set with `httpOnly: true`, `sameSite: 'lax'`, and `secure: true` in production environments to prevent cross-site scripting (XSS) token theft.

---

## 4. Rate Limiting & Defense-in-Depth

- **HTTP Rate Limiting:** Configured via `express-rate-limit` with a default window of 15 minutes and a threshold of 100 requests per IP address to mitigate denial-of-service (DoS) and brute-force credential stuffing.
- **Security Headers:** Enforced via `helmet` (Content-Security-Policy, X-DNS-Prefetch-Control, Strict-Transport-Security, Frameguard).
- **CORS Restrictions:** Configured with explicit origin whitelists, credential support, and allowed method restrictions.
- **Safe Error Handling:** Centralized error boundary prevents stack traces and database schema errors from leaking in production responses.
