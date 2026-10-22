# PhishNetra — Core REST API Reference

**Framework:** PhishNetra Multi-Layer Zero-Trust Phishing Detection  
**Base URL:** `http://localhost:5000/api`  
**Authentication:** Bearer JWT in `Authorization: Bearer <TOKEN>` header (Optional for public inspection; required for analyst actions)

---

## 1. Real-Time URL Threat Analysis (P0 Core)

### `POST /api/analyze`
Submits a target destination URL to the multi-layer evaluation pipeline.

**Request Body:**
```json
{
  "url": "http://secure-login-update-paypal-verification.com/account",
  "analyzePage": true
}
```

**Response (200 OK):**
```json
{
  "id": "ana_4c98a3b8-2e11",
  "url": "http://secure-login-update-paypal-verification.com/account",
  "normalizedUrl": "http://secure-login-update-paypal-verification.com/account",
  "domain": "secure-login-update-paypal-verification.com",
  "verdict": "PHISHING",
  "riskScore": 92.4,
  "riskLevel": "CRITICAL",
  "confidence": 0.96,
  "mlProbability": 0.94,
  "pageStatus": "COMPLETED",
  "summary": "High-confidence phishing destination targeting PayPal credentials with young domain and cross-origin forms.",
  "layerResults": {
    "lexical": { "score": 88.0, "status": "COMPLETED" },
    "domain": { "score": 95.0, "status": "COMPLETED", "ageDays": 2 },
    "dns": { "score": 70.0, "status": "COMPLETED" },
    "tls": { "score": 85.0, "status": "COMPLETED" },
    "reputation": { "score": 90.0, "status": "COMPLETED" },
    "ml": { "score": 94.0, "status": "COMPLETED" },
    "pageContent": { "score": 95.0, "status": "COMPLETED" }
  },
  "evidence": [
    {
      "layer": "PAGE_CONTENT",
      "severity": "CRITICAL",
      "description": "Brand Domain Mismatch: Page renders PayPal brand assets on non-official domain."
    },
    {
      "layer": "DOMAIN",
      "severity": "CRITICAL",
      "description": "Domain registered within the last 48 hours (Zero-Trust trigger)."
    }
  ],
  "createdAt": "2026-10-22T20:15:30.000Z"
}
```

---

### `GET /api/analyze/history`
Returns paginated historical scans and evaluation records.

**Query Parameters:**
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)

**Response (200 OK):**
```json
{
  "total": 142,
  "items": [
    {
      "id": "ana_4c98a3b8-2e11",
      "url": "http://secure-login-update-paypal-verification.com/account",
      "verdict": "PHISHING",
      "riskScore": 92.4,
      "riskLevel": "CRITICAL",
      "confidence": 0.96,
      "createdAt": "2026-10-22T20:15:30.000Z"
    }
  ]
}
```

---

### `GET /api/analyze/:id`
Retrieves detailed evidence, layer breakdowns, and DOM findings for a specific scan.

---

## 2. Email Attachment Hyperlink Ingestion (P0 Core)

### `POST /api/ingest/attachment`
Parses a supported email attachment, extracts all embedded hyperlinks, executes multi-layer URL evaluation on each extracted target, and synthesizes an explainable risk report.

**Supported Formats:** `PDF`, `HTML`, `DOCX`, `TXT`, `EML` (Maximum size: 10MB)

**Request Body:**
```json
{
  "filename": "Payroll_Update_Notice.pdf",
  "contentBase64": "JVBERi0xLjQKMSAwIG9iago8PA...",
  "maxUrlsToAnalyze": 15
}
```
*Alternatively, `rawText` may be supplied for plain text, HTML snippets, or RFC 822 EML content.*

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "analysisId": "att_6f18c0a9-bc4",
    "filename": "Payroll_Update_Notice.pdf",
    "detectedFormat": "PDF",
    "fileSizeBytes": 18450,
    "processingStatus": "THREATS_DETECTED",
    "totalUrlsExtracted": 3,
    "uniqueUrlsExtracted": 2,
    "overallVerdict": "PHISHING",
    "overallRiskScore": 89.5,
    "overallRiskLevel": "CRITICAL",
    "analyzedUrls": [
      {
        "id": "ana_781290",
        "url": "http://malicious-payroll-portal.com/auth",
        "verdict": "PHISHING",
        "riskScore": 89.5,
        "riskLevel": "CRITICAL",
        "confidence": 0.94,
        "createdAt": "2026-10-22T20:16:00.000Z"
      },
      {
        "id": "ana_781291",
        "url": "https://corporate-helpdesk.org/support",
        "verdict": "SAFE",
        "riskScore": 12.0,
        "riskLevel": "LOW",
        "confidence": 0.88,
        "createdAt": "2026-10-22T20:16:02.000Z"
      }
    ],
    "suspiciousOrMaliciousUrls": [
      "http://malicious-payroll-portal.com/auth"
    ],
    "unreachableUrls": [],
    "evidenceReasons": [
      "Extracted 3 embedded hyperlinks across PDF URI action dictionaries and annotations.",
      "Identified 1 high-risk phishing destination targeting organizational credentials."
    ],
    "warningNotes": [
      "Advisory: Do not open hyperlinks embedded in this attachment outside an isolated test sandbox."
    ],
    "disclaimer": "Security Note: This analysis evaluated embedded hyperlinks and target destination indicators. It does not constitute a full operating-system sandbox or local binary malware scan.",
    "analyzedAt": "2026-10-22T20:16:03.000Z"
  }
}
```

**Status Values:**
- `SUCCESS`: Clean processing with all URLs analyzed.
- `NO_SUSPICIOUS_URLS_FOUND`: File parsed successfully; zero embedded links or all links verified safe.
- `THREATS_DETECTED`: One or more extracted URLs were classified as `PHISHING` or `SUSPICIOUS`.
- `UNABLE_TO_ANALYZE`: File exceeded processing limits, was malformed, or has an unsupported binary format.

---

## 3. Domain Intelligence & Typosquatting (P1 Supporting)

### `GET /api/domains/:domain`
Retrieves aggregated domain age (RDAP), nameservers, MX records, and typosquatting risk scores.

### `POST /api/domains/typosquatting`
Generates and evaluates lookalike brand variations (Levenshtein distance, Cyrillic confusables, combosquatting).

---

## 4. Asynchronous Batch Queue (P1 Supporting)

### `POST /api/batch`
Submits bulk URL lists for asynchronous worker processing.

### `GET /api/batch/:id`
Retrieves live progress and completed item verdicts.

### `GET /api/batch/:id/export?format=csv|json`
Exports batch evaluation outcomes.

---

## 5. Health & Observability (P1 Supporting)

### `GET /api/health`
Standard service health probe returning dependency statuses (API, ML Service, Database).

### `GET /api/metrics`
Prometheus metrics scraping endpoint.

---

## 6. Deferred Endpoints (Preserved for Backward Compatibility)

The following modules remain mounted in the backend to ensure zero regression for existing automated tests and migrations, but are **deferred from the active product navigation**:
- `/api/siem/*` (SIEM format exporters)
- `/api/cases/*` (SOC case management)
- `/api/playbooks/*` (Autonomous SOAR playbooks)
- `/api/rbi/*` (Remote browser isolation container stubs)
- `/api/tarpit/*` (Phishing tarpit flooder)
- `/api/bgp-integrity/*` (BGP route integrity radar)
- `/api/fido2-guard/*` (FIDO2 authentication policy builder)
- `/api/cti-exchange/*` (TAXII 2.1 threat exchange)
