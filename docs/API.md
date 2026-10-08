# PhishNetra — REST API & Multi-Layer Reference

**Current Version:** `v0.4.0` (Milestone 4: Distributed Async Architecture, Batch Ingestion & Domain Hub)  
**Base URL:** `http://localhost:5000/api`

---

## 1. Authentication Endpoints

### `POST /auth/register`
Creates a new analyst account.
- **Request Body:**
  ```json
  {
    "name": "SOC Analyst",
    "email": "analyst@phishnetra.dev",
    "password": "SecurePassword2026!"
  }
  ```
- **Response (201 Created):**
  ```json
  {
    "user": {
      "id": "uuid",
      "name": "SOC Analyst",
      "email": "analyst@phishnetra.dev",
      "role": "USER",
      "createdAt": "2026-09-03T16:00:00.000Z"
    },
    "token": "eyJhbGciOiJIUzI1NiIsIn..."
  }
  ```

### `POST /auth/login`
Authenticates existing credentials.

---

## 2. Multi-Layer Threat Analysis Endpoints

### `POST /analyze`
Performs comprehensive synchronous multi-layer threat analysis on candidate URL.

- **Request Body:**
  ```json
  {
    "url": "https://paypal.com/signin",
    "analyzePage": true
  }
  ```

- **Response (200 OK):**
  Returns complete multi-layer breakdown, risk score, confidence, isolated DOM/Brand analysis, and structured evidence array.

### `GET /analyze/history`
Returns paginated historical scans for the authenticated analyst.

### `GET /analyze/:id`
Retrieves full investigation report by analysis ID.

---

## 3. Asynchronous Batch Ingestion Endpoints (Milestone 4)

### `POST /batch`
Submits an array, multiline string, or CSV list of URLs to the async worker queue.

- **Request Body:**
  ```json
  {
    "urls": [
      "https://example-phish.com",
      "https://paypal.com",
      "https://unverified-login-portal.org"
    ],
    "includePageAnalysis": false
  }
  ```
- **Response (202 Accepted):**
  ```json
  {
    "id": "b812f8e1-d52b-4fa8-b219-fc35c630129a",
    "status": "QUEUED",
    "totalUrls": 3,
    "processedUrls": 0,
    "safeCount": 0,
    "suspiciousCount": 0,
    "phishingCount": 0,
    "failedCount": 0,
    "avgRiskScore": 0.0,
    "progressPercent": 0,
    "createdAt": "2026-10-08T10:30:00.000Z",
    "items": [ ... ]
  }
  ```

### `GET /batch/:id`
Polls live execution progress, summary counters, and item-level analysis outcomes for a batch job.

### `GET /batch`
Returns a paginated list of previous batch jobs submitted by the analyst.

### `POST /batch/:id/cancel`
Cancels any remaining unexecuted URLs in an active batch queue.

### `GET /batch/:id/export?format=csv|json`
Downloads batch scan results formatted as a downloadable CSV or JSON report.

---

## 4. Domain Dossier & Typosquatting Endpoints (Milestone 4)

### `GET /domains/:domain`
Aggregates WHOIS/RDAP age categorization, DNS nameservers, historical scans, and typosquatting threat matrices for a specific domain.

- **Response (200 OK):**
  ```json
  {
    "domain": "google.com",
    "registrableDomain": "google.com",
    "domainAgeDays": 10582,
    "ageCategory": "> 365 days",
    "registrar": "MarkMonitor, Inc.",
    "nameservers": ["ns1.google.com", "ns2.google.com"],
    "ipAddresses": ["142.250.190.46"],
    "totalScans": 14,
    "phishingScans": 0,
    "riskScore": 15,
    "riskLevel": "LOW",
    "typosquattingAlerts": [
      {
        "variant": "g00gle.com",
        "targetBrand": "Google",
        "officialDomain": "google.com",
        "type": "HOMOGLYPH",
        "similarityScore": 98,
        "riskLevel": "CRITICAL",
        "explanation": "Lookalike digit substitution (0 -> o) targeting Google."
      }
    ]
  }
  ```

### `POST /domains/typosquatting`
Generates and inspects simulated typosquatting, Cyrillic homoglyph, and combosquatting permutations on demand.

---

## 5. Community Threat Reports & Moderation Endpoints (Milestone 4)

### `POST /reports`
Submits a crowdsourced threat indicator or false-positive remediation report.

- **Request Body:**
  ```json
  {
    "url": "https://suspicious-brand-login.com",
    "reportType": "PHISHING",
    "description": "SMS lure claiming suspended account asking for credentials.",
    "evidenceDetails": "Form action posts to raw IP address 185.220.101.5"
  }
  ```

### `GET /reports?status=PENDING&reportType=PHISHING`
Filters and lists community reports.

### `PATCH /reports/:id/moderate` *(Requires Analyst / Admin JWT)*
Updates moderation status (`APPROVED`, `REJECTED`, `RESOLVED`) and records analyst notes.

---

## 6. System & Observability Telemetry Endpoints (Milestone 4)

### `GET /system/metrics`
Returns combined metrics on active background worker queues and persistent cache hit ratios.

### `GET /system/queue`
Returns queue length, active workers, concurrency limit, and completed task totals.

### `GET /system/cache`
Returns cache driver (`memory` | `redis`), key count, memory usage in MB, and hit ratio.

