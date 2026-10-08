# PhishNetra — System Threat Model (STRIDE)

## 1. Overview & Trust Boundaries

PhishNetra processes untrusted external URLs, raw emails, DOM content, and analyst inputs across distributed network boundaries.

```
[ User / Browser Extension ]
          │ (HTTPS / Bearer Token)
          ▼
   [ Node.js API Gateway ] ◄───► [ PostgreSQL / Redis Cache ]
          │ (Internal HTTP / mTLS)
          ▼
   [ Python ML Service ] ───► [ Isolated Headless Browser ] ───► [ External Untrusted Web ]
```

---

## 2. STRIDE Threat Analysis

### S — Spoofing (Identity & Authority)
- **Threat:** Malicious actors attempting to bypass API authentication or forge analyst identity.
- **Mitigation:**
  - JWT authentication with secure HMAC-SHA256 tokens and configurable expirations.
  - Granular RBAC (`USER`, `ANALYST`, `ADMIN`) enforced via `authMiddleware.ts`.
  - Cryptographic API key validation with sha256 hashing and 1-click revocation.

### T — Tampering (Data Integrity)
- **Threat:** Adversaries modifying scan results, disabling detection rules, or poisoning retraining corpora.
- **Mitigation:**
  - Structured immutable SOC Audit Trail logging all security events with IP and actor tracking.
  - Strict input validation via Zod schemas in TypeScript and Pydantic in Python.
  - Moderation workflow for community threat reports preventing automated ground-truth pollution.

### R — Repudiation (Accountability)
- **Threat:** Analysts denying executing remediation actions or administrative changes.
- **Mitigation:**
  - Mandatory audit log recording with user ID, timestamps, IP addresses, and before/after payloads for configuration changes.

### I — Information Disclosure (Data Leakage)
- **Threat:** Exposure of internal IP addresses, database schemas, or cloud IAM metadata via SSRF or error stack traces.
- **Mitigation:**
  - Centralized Express error handler (`errorHandler.ts`) masking internal stack traces in production (`NODE_ENV=production`).
  - Strict SSRF filtering (`ssrf.py`) blocking private RFC 1918, loopback, and cloud metadata (`169.254.169.254`).
  - Playwright browser execution in sandboxed network contexts.

### D — Denial of Service (Availability)
- **Threat:** Attackers overwhelming the scanning engine with high-volume URL batches or recursive redirect chains.
- **Mitigation:**
  - Global API rate limiting via `express-rate-limit`.
  - Concurrency-controlled BullMQ async worker queues with job timeout safeguards.
  - Playwright request timeout caps (10s), response size limits (5MB), and maximum redirect depth limits.

### E — Elevation of Privilege (Access Control)
- **Threat:** Standard users manipulating parameters to access administrative calibration settings or SIEM webhooks.
- **Mitigation:**
  - Strict role authorization gates on sensitive endpoints (`requireRole('ADMIN')`, `requireRole('ANALYST')`).
  - Parameter tampering protection in Prisma ORM preventing SQL injection.
