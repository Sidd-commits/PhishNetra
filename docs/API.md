# PhishNetra — REST API Reference & Endpoint Specification

**Official Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Specification:** Semester 1 Endpoint Reference  
**Base URL:** `http://localhost:5000/api` (Backend Express Core)  
**ML Microservice URL:** `http://127.0.0.1:8000` (FastAPI Python Engine)  
**Authentication:** Optional Bearer JWT (`Authorization: Bearer <TOKEN>`) or API Key (`x-api-key: <KEY>`)  

---

## 1. Semester 1 Operational Endpoints (Core In-Scope)

### 1.1 Real-Time URL Threat Analysis

#### `POST /api/analyze`
Submits a target destination URL to the multi-layer evaluation pipeline.

**Request Schema:**
```json
{
  "url": "http://secure-login-update-paypal-verification.com/account",
  "analyzePage": false
}
```
*Note: `analyzePage` defaults to `false` for sub-second analysis; set to `true` to invoke sandboxed DOM fetching.*

**Representative Response (200 OK):**
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
  "pageStatus": "SKIPPED",
  "summary": "High-confidence phishing destination targeting PayPal credentials with young domain (<48h) and high lexical entropy.",
  "layerResults": {
    "lexical": { "score": 88.0, "status": "COMPLETED" },
    "domain": { "score": 95.0, "status": "COMPLETED", "ageDays": 2 },
    "dns": { "score": 70.0, "status": "COMPLETED" },
    "tls": { "score": 85.0, "status": "COMPLETED" },
    "reputation": { "score": 90.0, "status": "COMPLETED" },
    "ml": { "score": 94.0, "status": "COMPLETED" }
  },
  "evidence": [
    {
      "layer": "DOMAIN",
      "severity": "CRITICAL",
      "description": "Domain registered within the last 48 hours (Zero-Trust trigger)."
    },
    {
      "layer": "LEXICAL",
      "severity": "HIGH",
      "description": "High Shannon entropy (4.32) and suspicious brand token 'paypal' in unverified hostname."
    }
  ],
  "createdAt": "2026-10-22T20:15:30.000Z"
}
```

---

#### `GET /api/analyze/history`
Retrieves paginated historical evaluation records.

**Query Parameters:**
- `limit` (integer, default: 20, max: 100)
- `offset` (integer, default: 0)

**Representative Response (200 OK):**
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

#### `GET /api/analyze/:id`
Retrieves complete layer telemetry, individual layer scores, and structured evidence for a previously executed scan.

---

### 1.2 Email Attachment Link Ingestion

#### `POST /api/ingest/attachment`
Parses a supported email attachment in-memory, extracts embedded hyperlinks without code execution, and evaluates extracted URLs through the multi-layer threat pipeline.

**Supported Formats:** `PDF`, `HTML`, `DOCX`, `TXT`, `EML` (Maximum size: 10MB)

**Request Schema:**
```json
{
  "filename": "Payroll_Update_Notice.pdf",
  "contentBase64": "JVBERi0xLjQKMSAwIG9iago8PA...",
  "maxUrlsToAnalyze": 15
}
```
*Alternatively, `rawText` may be provided for plain text or RFC 822 EML content.*

**Representative Response (200 OK):**
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
    "disclaimer": "Security Note: This analysis evaluated embedded hyperlinks and target destination indicators. It does not constitute a full operating-system sandbox or local binary malware scan.",
    "analyzedAt": "2026-10-22T20:16:03.000Z"
  }
}
```

**Verdict Status Values:**
- `SUCCESS`: Parsing clean; all URLs processed successfully.
- `NO_SUSPICIOUS_URLS_FOUND`: File parsed cleanly; zero URLs detected or all extracted links verified safe.
- `THREATS_DETECTED`: One or more extracted URLs classified as `PHISHING` or `SUSPICIOUS`.
- `UNABLE_TO_ANALYZE`: File format unsupported, corrupted, or exceeds the 10MB ceiling.

---

### 1.3 Supporting Utilities (In-Scope)

#### `GET /api/domains/:domain`
Retrieves aggregated domain age (RDAP), nameservers, MX records, and typosquatting risk scores.

#### `POST /api/domains/typosquatting`
Generates and evaluates lookalike brand variations using Levenshtein distance, Cyrillic confusables, and combosquatting patterns.

#### `POST /api/batch` & `GET /api/batch/:id`
Enqueues bulk URL lists for asynchronous worker evaluation with progress reporting and CSV/JSON export.

#### `GET /api/health`
Standard service health check returning statuses of backend services and database connections.

---

### 1.4 Unified Classification Policy & Risk Thresholds

All API responses, UI components, and the browser extension adhere to a single unified risk score boundary policy defined in `@phishnetra/shared`:

| Composite Risk Score | Classification Verdict | Risk Level | Browser Mitigation Action |
| :---: | :---: | :---: | :--- |
| **0.00 – 34.99** | `SAFE` | `LOW` | Allowed (Green Badge `OK`, no interstitial) |
| **35.00 – 69.99** | `SUSPICIOUS` | `MEDIUM` | Warning banner in popup (Yellow Badge `WARN`) |
| **70.00 – 79.99** | `PHISHING` | `HIGH` | **Full-Screen Interstitial Barrier** (`interstitial.ts`, Red Badge `BLOCK`) |
| **80.00 – 100.00** | `PHISHING` | `CRITICAL` | **Full-Screen Interstitial Barrier** with Critical Indicators |

#### Zero-Trust Deterministic Overrides
- **Domain Age $< 48$ Hours:** Risk score forced $\ge 70.0$ (`PHISHING`).
- **Threat Feed Blacklist Match:** Risk score forced $\ge 90.0$ (`CRITICAL / PHISHING`).
- **Raw IP Hostname with Password Input:** Risk score forced $\ge 90.0$ (`CRITICAL / PHISHING`).
- **Punycode Confusable / Homoglyph Spoof:** Risk score forced $\ge 85.0$ (`CRITICAL / PHISHING`).
- **Combosquatting on High-Abuse TLD (`.xyz`, `.top`, etc.):** Risk score forced $\ge 80.0$ (`CRITICAL / PHISHING`).
- **Verified Authentic Brand Domain (SSO / Official Portal):** Negative risk dampener caps composite risk $\le 18.0$ (`SAFE`).

---

## 2. Python ML Microservice Endpoints (`:8000`)

### `POST /predict`
Fast Random Forest inference on 18 deterministic lexical features. Returns phishing probability, classification verdict, and confidence score.

### `POST /analyze-page`
Sandboxed webpage fetcher operating with strict SSRF immunity. Inspects DOM form action destinations and tests against the 15-brand catalog for domain mismatch.

### `POST /explain`
Computes Tree-SHAP feature attributions and generates natural-language explainable narratives.

### `GET /health`
Returns microservice operational status and loaded model metadata.

---

## 3. Explicitly Deferred Endpoints (Preserved for Backward Compatibility)

The following modules remain mounted in the backend to ensure zero regression for existing automated tests and database migrations, but are **excluded from the active academic presentation**:

| Endpoint Route | Original Purpose | Current Status |
| :--- | :--- | :---: |
| `/api/cases/*` | SOC Incident Case Management | Deferred (Enterprise) |
| `/api/playbooks/*` | Autonomous SOAR Playbook Execution | Deferred (Enterprise) |
| `/api/siem/*` | Syslog & SIEM Event Forwarders | Deferred (Enterprise) |
| `/api/rbi/*` | Remote Browser Isolation Stubs | Deferred (Enterprise) |
| `/api/tarpit/*` | Phishing Tarpit Flooder | Deferred (Enterprise) |
| `/api/bgp-integrity/*` | BGP Route Integrity Radar | Deferred (Enterprise) |
| `/api/fido2-guard/*` | FIDO2 Credential Guard Admin | Deferred (Enterprise) |
| `/api/cti-exchange/*` | TAXII 2.1 Threat Exchange | Deferred (Enterprise) |
