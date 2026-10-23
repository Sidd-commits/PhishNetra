# PhishNetra 🛡️

> **A Multi-Layered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation**

[![Academic Classification](https://img.shields.io/badge/Academic%20Project-Two--Semester%20Major%20Project-cyan.svg)](docs/PROJECT_SCOPE.md)
[![Milestone](https://img.shields.io/badge/Milestone-Semester%201%20Deliverable%20Verified-blue.svg)](docs/SEMESTER_MILESTONE_AUDIT.md)
[![Automated Tests](https://img.shields.io/badge/Tests-262%2F262%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![Node.js](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Chrome Extension](https://img.shields.io/badge/Extension-Manifest%20V3-orange.svg)](apps/extension/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Executive Summary & Academic Project Scope

**PhishNetra** is an integrated cybersecurity research and engineering framework designed to overcome the critical limitations of conventional, reactive phishing defenses. Modern phishing campaigns rely on fast-flux DNS, freshly registered lookalike domains, subtle Unicode homoglyphs, and evasive delivery vectors—notably **embedded URLs inside email attachments (PDF, HTML, DOCX, TXT, EML)**—that bypass static URL blacklists due to multi-hour or multi-day indexing dwell times.

PhishNetra is developed as a **two-semester academic major project spanning approximately ten months**:

```
+---------------------------------------------------------------------------------------------------+
|                               PHISHNETRA TWO-SEMESTER TIMELINE                                     |
+---------------------------------------------------------------------------------------------------+
|  SEMESTER 1 (Months 1 → 5): Core Research Prototype & Proof of Concept [DELIVERED & VERIFIED]    |
|  • Multi-Layer Zero-Trust URL Threat Pipeline (Lexical, RDAP Age, DNS, TLS, Feeds, ML)            |
|  • Calibrated Baseline Machine Learning Classifier (Random Forest + Tree-SHAP Explainability)     |
|  • Email Attachment Link Extraction Vertical Slice (PDF, HTML, DOCX, TXT, EML)                     |
|  • Chrome Manifest V3 Browser Extension Prototype (<5ms Heuristics + DOM Interstitial Barrier)    |
|  • Unified Academic Security Console (React 18 + Vite Dashboard, Scanners, Telemetry History)     |
|  VERIFICATION: 262/262 Automated Tests Passing (100%) • 4/4 Workspaces Clean Production Builds    |
+---------------------------------------------------------------------------------------------------+
|  SEMESTER 2 (Months 6 → 10): Empirical Evaluation, Hardening & Academic Thesis [PLANNED ROADMAP] |
|  • Comprehensive Benchmark Dataset Evaluation (Precision, Recall, F1, ROC-AUC on PhishTank/Alexa) |
|  • Extension Lifecycle Hardening (chrome.declarativeNetRequest Rulesets, Zero First-Byte Leakage) |
|  • Extended File Format Coverage (OpenXML XLSX/PPTX, RTF, Redirect Chain Unmasking)               |
|  • Computer Vision Logo Similarity Prototype (YOLO/CLIP Visual Brand Matching vs DOM Forms)       |
|  • Dynamic Layer Weight Calibration via Validation Loss & End-to-End Latency Profiling            |
|  • Academic Thesis Dissertation, Usability Evaluation on Warning Compliance & Final Defense        |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Research Problem & Engineering Objectives

PhishNetra addresses six fundamental research and engineering questions:

1. **Is the target URL suspicious or malicious?**  
   Evaluated deterministically across lexical entropy, token structures, domain age, DNS infrastructure anomalies, TLS certificate validity, and machine learning inference.
2. **What concrete evidence justifies the verdict?**  
   Synthesized through an explainable Zero-Trust evidence engine attributing individual layer scores, confidence ratings, and Tree-SHAP feature contributions.
3. **Does the rendered webpage exhibit credential-harvesting indicators?**  
   Inspected in an isolated, SSRF-protected sandboxed fetcher evaluating cross-origin form actions, raw IP form destinations, and a 15-enterprise brand catalog for `BRAND_DOMAIN_MISMATCH`.
4. **Does an email attachment contain hidden phishing destinations?**  
   Safely parsed in memory using declarative pure-JavaScript string and stream decoders (PDF, HTML, DOCX, TXT, EML) without executing active code, followed by automated multi-layer evaluation of extracted links.
5. **Can the browser extension protect the user before credentials are stolen?**  
   Engineered as a Manifest V3 extension executing instant sub-5ms local heuristics, dynamic toolbar badge signaling, and an un-bypassable DOM security barrier overlay (`interstitial.ts`).
6. **What actionable choices does the user have upon threat interception?**  
   Enforces three conscious, non-silent choices: **Return to Safety (Recommended)**, **Inspect SOC Evidence (Deep Link to Web Console)**, or **Conscious Session Bypass**.

---

## 3. Operational System Architecture (Semester 1 Baseline)

All inputs—direct URL submissions, batch jobs, email attachments, and real-time browser extension requests—flow through a unified, shared canonicalization and multi-layer Zero-Trust evaluation pipeline:

```text
                               ┌────────────────────────────────────────────────────────┐
                               │             Client & Endpoint Tier                     │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
                        ┌──────────────────────────────────┴──────────────────────────────────┐
                        │                                                                     │
                        ▼                                                                     ▼
         ┌─────────────────────────────┐                                       ┌─────────────────────────────┐
         │ React Security Console      │                                       │ Chrome Extension (MV3)      │
         │ • Dashboard Overview        │                                       │ • tabs.onUpdated Hook       │
         │ • Live URL Scanner          │                                       │ • Sub-5ms Local Heuristics  │
         │ • Attachment Link Scanner   │                                       │ • CHECK_PAGE_THREAT Query   │
         │ • Telemetry History         │                                       │ • DOM Interstitial Barrier  │
         └──────────────┬──────────────┘                                       └──────────────┬──────────────┘
                        │                                                                     │
                        └──────────────────────────────────┬──────────────────────────────────┘
                                                           │ (HTTP/REST POST /api/analyze)
                                                           ▼
                                            ┌─────────────────────────────┐
                                            │ Node.js Backend API Core    │
                                            │ Express + TS + Zod Schemas  │
                                            └──────────────┬──────────────┘
                                                           │
         ┌─────────────────────────────────────────────────┼─────────────────────────────────────────────────┐
         ▼                                                 ▼                                                 ▼
┌──────────────────────────────┐              ┌──────────────────────────────┐              ┌──────────────────────────────┐
│ Ingestion & Pre-Processing   │              │ Multi-Layer Risk Engine      │              │ Data & Caching Tier          │
│ • URL Canonicalizer (RFC3986)│              │ • Layer 1: Lexical (16 feat) │              │ • In-Memory LRU Cache        │
│ • Punycode / IDN Normalizer  │              │ • Layer 2: RDAP Domain Age   │              │ • Redis Distributed Cache    │
│ • Attachment Link Extractor  │              │ • Layer 3: Passive DNS / IP  │              │   (with offline fallback)    │
│   (PDF, HTML, DOCX, TXT, EML)│              │ • Layer 4: TLS Socket Struct │              │ • PostgreSQL & Prisma ORM    │
└──────────────────────────────┘              │ • Layer 5: Threat Feeds Rep  │              │   (Analyses, Users, Queue)   │
                                              │ • Layer 6: ML Random Forest  │              └──────────────────────────────┘
                                              │ • Layer 7: Webpage DOM & Form│
                                              └──────────────┬───────────────┘
                                                             │
                                                             ▼
                                              ┌──────────────────────────────┐
                                              │ Zero-Trust Decision Engine   │
                                              │ • Layer Weight Normalization │
                                              │ • Zero-Trust Overrides       │
                                              │   (Fresh Domain, Blacklist)  │
                                              │ • NaN-Safe Score (0–100)     │
                                              │ • Tree-SHAP Evidence Engine  │
                                              │ • Verdict: SAFE / SUSPICIOUS │
                                              │   / PHISHING                 │
                                              └──────────────────────────────┘
```

---

## 4. Repository Monorepo Structure

```text
PhishNetra/
│
├── apps/
│   ├── api/                     # Node.js + Express + TypeScript Backend Core
│   │   ├── src/controllers/     # REST Controllers (Analysis, Ingest, Domains, Queue, Auth, Reports)
│   │   ├── src/services/        # Multi-Layer Threat Pipeline & Attachment Parsers
│   │   │   ├── analysis/        # Canonicalization, Lexical, DNS, TLS, RDAP, Reputation, Typosquatting
│   │   │   ├── ingestion/       # Safe pure-JS attachment link extraction (PDF/HTML/DOCX/TXT/EML)
│   │   │   └── risk/            # Zero-Trust Risk Engine & Evidence Engine
│   │   └── tests/               # 192 Jest + Supertest automated suites (100% passing)
│   │
│   ├── web/                     # React 18 + Vite + Tailwind CSS Security Console
│   │   ├── src/pages/           # Dashboard, Analyze, Attachments, Domains, Batch, History, Settings, Extension
│   │   ├── src/components/      # Multi-Layer Breakdown, Gauge, Evidence Tables, Interstitial Preview
│   │   └── src/services/        # Typed API client with JWT & API key support
│   │
│   └── extension/               # Chrome Manifest V3 Browser Extension
│       ├── src/background/      # Service worker, sub-5ms local heuristics, badge manager, tab state map
│       ├── src/content/         # Content script, un-bypassable DOM interstitial barrier, warning banner
│       ├── src/popup/           # Extension toolbar popup UI, live tab inspection, whitelist toggle
│       └── tests/               # 12 Jest unit tests (100% passing)
│
├── services/
│   └── ml/                      # Python 3.10 + FastAPI Machine Learning Microservice
│       ├── app/api/             # Endpoints (/predict, /analyze-page, /explain, /health)
│       ├── app/model/           # Random Forest classifier pipeline, model registry, versioning
│       ├── app/features/        # Deterministic 18-feature lexical/syntactic extractor
│       ├── app/analyzer/        # Sandboxed webpage DOM fetcher with strict SSRF immunity
│       └── tests/               # 58 Pytest automated ML & SSRF test cases (100% passing)
│
├── packages/
│   └── shared/                  # Shared TypeScript types, Zod schemas, & constants
│
├── docs/                        # Authoritative Technical Documentation & Milestone Audits
│   ├── SEMESTER_MILESTONE_AUDIT.md # Definitive capability audit & technical verification evidence
│   ├── PROJECT_SCOPE.md         # Official scope & two-semester specifications
│   ├── ROADMAP.md               # Two-semester academic roadmap & acceptance criteria
│   ├── ARCHITECTURE.md          # System architecture (current baseline vs planned evolution)
│   ├── API.md                   # REST API endpoint reference (in-scope vs deferred)
│   ├── IMPLEMENTATION_STATUS.md # Current verification report (262 tests passing)
│   └── SECURITY.md              # Zero-Trust invariants & vulnerability defenses
│
├── prisma/
│   └── schema.prisma            # Database schema (Users, Analyses, Evidence, BatchJobs, Reports)
│
├── package.json                 # Monorepo workspaces & build orchestration
└── LICENSE                      # MIT License
```

---

## 5. The Multi-Layer Zero-Trust Threat Engine (8 Layers)

PhishNetra enforces a non-negotiable Zero-Trust invariant: **no single signal determines safety**. A destination with a valid TLS certificate and clean legacy blacklists will still be classified as **PHISHING** if domain age is fresh, DNS exhibits fast-flux routing, form actions point cross-origin, or brand mismatches are identified.

```
+-------+-----------------------------+--------------------------------------------------------------+
| Layer | Layer Name                  | Evaluated Signals & Zero-Trust Invariants                    |
+-------+-----------------------------+--------------------------------------------------------------+
| L0    | URL Canonicalization Engine | RFC 3986 normalization, scheme lowercasing, default port     |
|       |                             | removal (80/443), Punycode/IDN homoglyph translation,        |
|       |                             | duplicate slash collapsing, trailing dot stripping.          |
| L1    | Lexical Structural Engine   | 16 deterministic features: Shannon entropy, path depth, token|
|       |                             | count, IP-literal hostnames, userinfo (@) credential tricks, |
|       |                             | suspicious TLDs (.xyz, .top, .click, etc.), URL shorteners.  |
| L2    | Domain Intelligence (RDAP)  | Domain registration freshness: <30d, 30–90d, 90–365d, >365d. |
|       |                             | ZERO-TRUST OVERRIDE: Domains registered within <48 hours     |
|       |                             | immediately elevate risk to HIGH/CRITICAL.                   |
| L3    | Passive DNS & SSRF Guard    | A, AAAA, MX, NS records. Identifies fast-flux TTL anomalies.  |
|       |                             | Pre-flight socket filter blocks RFC 1918 private subnets,    |
|       |                             | loopback, and cloud metadata (169.254.169.254).             |
| L4    | TLS Certificate Validation  | Validates hostname against certificate Subject Alternative   |
|       |                             | Names (SANs), checks validity lifetime, flags self-signed    |
|       |                             | certificates and unencrypted HTTP endpoints.                 |
| L5    | Threat Feeds & Reputation   | URLhaus, local blocklists, and provider abstraction.         |
|       |                             | ZERO-TRUST OVERRIDE: Active blacklist hit immediately sets   |
|       |                             | verdict to PHISHING regardless of other signals.             |
| L6    | Baseline Machine Learning   | Fast (<5ms) Random Forest classifier trained on 18 features. |
|       |                             | Returns probability, binary verdict, and Tree-SHAP           |
|       |                             | feature attribution explaining why the link was flagged.     |
| L7    | Sandboxed Webpage DOM       | Isolated browser fetcher with SSRF defense. Inspects form    |
|       |                             | action destinations (cross-origin password targets, raw IP   |
|       |                             | targets) and checks 15 enterprise brands for domain mismatch.|
+-------+-----------------------------+--------------------------------------------------------------+
```

---

## 6. Baseline Machine Learning & SHAP Explainability

### Model Specifications
- **Algorithm:** Calibrated Random Forest Classifier (`scikit-learn`, 100 estimators, max depth 12).
- **Service Tier:** Python 3.10 + FastAPI microservice (`services/ml`) operating at `http://127.0.0.1:8000`.
- **Latency:** Sub-5ms inference per URL.
- **Explainability:** Tree-SHAP (SHapley Additive exPlanations) computes individual feature importance values and produces natural-language explanations for SOC analysts and end users.

### Deterministic Feature Vector (18 Features)
1. `url_length`: Total character count of normalized URL.
2. `hostname_length`: Length of fully qualified domain name.
3. `path_length`: Character length of the URL path component.
4. `count_dots`: Total count of period delimiters (`.`).
5. `count_hyphens`: Count of hyphens (`-`) (frequently used in brand combosquatting).
6. `count_at`: Presence of userinfo credential delimiter (`@`).
7. `count_question`: Count of query parameters (`?`).
8. `count_percent`: Count of percent-encoded characters (`%`).
9. `count_digits`: Total numeric digit count in URL.
10. `count_subdomains`: Depth of subdomain labels excluding TLD and `www`.
11. `has_ip`: Binary flag indicating raw IPv4 address used as hostname.
12. `shannon_entropy`: Information entropy of the hostname string (randomness metric).
13. `is_punycode`: Detection of `xn--` internationalized homoglyph encoding.
14. `suspicious_tld`: Match against known high-abuse TLDs.
15. `brand_keyword_count`: Frequency of sensitive brand keywords (e.g., `paypal`, `login`, `bank`).
16. `has_sensitive_keyword`: Binary flag indicating presence of security credential lures.
17. `non_standard_port`: Detection of non-default HTTP/HTTPS ports.
18. `path_depth`: Number of slash delimiters in the URL path.

---

## 7. Email Attachment Link Extraction Engine (Vertical Slice)

### The Evasive Attack Vector
Adversaries increasingly deliver phishing lures inside email attachments rather than in the email body to bypass basic gateway filters. PhishNetra provides a safe, pure-JavaScript link extraction pipeline that unpacks supported formats without executing code.

```
Uploaded Attachment (PDF / HTML / DOCX / TXT / EML)
                        │
                        ▼ (Pure-JS In-Memory Stream)
          ┌───────────────────────────┐
          │ Strict Safety Boundaries: │
          │ • Max Size: 10MB          │
          │ • Regex Catastrophic Def. │
          │ • ZERO Code Execution     │
          │ • ZERO Binary Execution   │
          └─────────────┬─────────────┘
                        │
                        ▼
          ┌───────────────────────────┐
          │ Format-Specific Parsing:  │
          │ • PDF: URI Action Dicts   │
          │ • HTML: a href, form, meta│
          │ • DOCX: OpenXML Rel XML   │
          │ • TXT/EML: Plain & Defang │
          └─────────────┬─────────────┘
                        │
                        ▼
          ┌───────────────────────────┐
          │ URL Normalization & Dedup │
          └─────────────┬─────────────┘
                        │
                        ▼
          ┌───────────────────────────┐
          │ Multi-Layer Threat Engine │
          │ (All Extracted Hyperlinks)│
          └─────────────┬─────────────┘
                        │
                        ▼
          ┌──────────────────────────────────────────────────────────┐
          │ Distinct Outcome Taxonomy:                               │
          │ • THREATS_DETECTED: Malicious embedded links identified  │
          │ • NO_SUSPICIOUS_URLS_FOUND: Clean parsed document        │
          │ • UNABLE_TO_ANALYZE: Malformed / password protected      │
          └──────────────────────────────────────────────────────────┘
```

### Safety & Scope Boundaries
- **Passive In-Memory Parsing:** Employs declarative regular expressions and XML decoders. **Never executes macros, active content, or shell scripts.**
- **Scope Disclaimer:** PhishNetra evaluates embedded hyperlinks and target destination indicators. It does **not** constitute an operating-system sandbox or binary executable malware scanner.

---

## 8. Chrome Manifest V3 Browser Extension

The PhishNetra extension provides real-time browser-level threat mitigation:

```
[Tab Navigation Initiated]
          │
          ▼
[Background Service Worker (serviceWorker.ts)]
          │
          ├── Sub-5ms Local Heuristics (<5ms)
          │   (Entropy, Punycode, IP Hostname, Suspicious TLD)
          │
          └── Asynchronous Threat Query (POST /api/analyze)
                      │
                      ▼
          [Composite Risk Score >= 70 or PHISHING?]
             ├── NO  ──> Set Badge OK/WARN, Allow Navigation
             │
             └── YES ──> [Zero Silent Redirects Policy]
                         Inject Un-Bypassable DOM Interstitial Barrier
                         (interstitial.ts, z-index: 2147483647)
                                      │
                         ┌────────────┴────────────┐
                         │ User Choice Required:   │
                         │ 1. Return to Safety     │
                         │ 2. Inspect SOC Evidence │
                         │ 3. Conscious Bypass     │
                         └─────────────────────────┘
```

### Key Technical Capabilities
1. **Zero Silent Redirects Policy:** Malicious navigation is stopped by an in-DOM interstitial overlay displaying composite risk scores, threat level, and critical indicator reasons. Automated silent redirects are strictly forbidden.
2. **Proactive `CHECK_PAGE_THREAT` Messaging:** The content script queries page status upon initialization, eliminating message-drop race conditions during early navigation.
3. **Privacy Invariant:** Content scripts never inspect form input values, passwords, keystrokes, or browser history. Permissions are strictly confined to `activeTab`, `tabs`, `storage`, and `scripting`.

---

## 9. Academic Web Security Console (`apps/web`)

The frontend is a fast, responsive Single Page Application built with **React 18 + Vite + TypeScript + Tailwind CSS**:

| Page / Route | Primary Capabilities |
| :--- | :--- |
| **Dashboard** ([`/dashboard`](http://localhost:5173/dashboard)) | Live telemetry overview, threat counters, active Zero-Trust status bar, recent analysis audit log. |
| **URL Threat Scanner** ([`/analyze`](http://localhost:5173/analyze)) | Interactive URL evaluation with 8-layer breakdown, risk gauge, SHAP narrative, and raw feature viewer. |
| **Attachment Scanner** ([`/attachments`](http://localhost:5173/attachments)) | Drag-and-drop file upload, 4 demo presets (PDF, HTML, DOCX, TXT), extracted link breakdown table. |
| **Domain Dossier Hub** ([`/domains`](http://localhost:5173/domains)) | RDAP registration age timeline, nameservers, MX records, lookalike typosquatting generator. |
| **Batch URL Scanner** ([`/batch`](http://localhost:5173/batch)) | Bulk URL list submission, asynchronous BullMQ worker processing, progress bar, CSV/JSON export. |
| **Telemetry History** ([`/history`](http://localhost:5173/history)) | Searchable, filterable audit log of evaluated targets with pagination, deep links, and JSON export. |
| **Extension Showcase** ([`/extension`](http://localhost:5173/extension)) | Visual extension lifecycle diagram, developer setup steps, interactive warning modal preview. |
| **System Settings** ([`/settings`](http://localhost:5173/settings)) | Dynamic risk layer weights, risk thresholds, provider toggles (URLhaus, PhishTank), API key generation. |

---

## 10. Zero-Trust Security Controls & Invariants

| Threat Vector | Mitigation Strategy & Verification |
| :--- | :--- |
| **Server-Side Request Forgery (SSRF)** | Pre-flight DNS resolution and socket-level filtering block loopback (`127.0.0.0/8`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and AWS/GCP cloud metadata (`169.254.169.254`). Alternative hex/octal IP notations are normalized prior to resolution (verified by 26 automated tests). |
| **DNS Rebinding (TOCTOU)** | Target hostname is resolved immediately prior to TCP handshake; aborts if resolved destination points to an internal boundary. |
| **Redirect Hop Pivoting** | Each redirect hop (`301`, `302`, `307`, `308`) is re-checked against the SSRF engine. Hard cap of 5 hops maximum. |
| **Attachment Code Execution** | Files are parsed in memory using declarative string decoders and regular expressions. Macros, active scripts, and binary payloads are never executed. |
| **Fail-Safe Principle** | Missing upstream intelligence or timeouts never default to a `SAFE` verdict. Unknown or failed signals receive `SUSPICIOUS` or `UNABLE_TO_ANALYZE`. |

---

## 11. Verification & Test Suite Baseline

```
================================================================================
                    PHISHNETRA MONOREPO VERIFICATION BASELINE
================================================================================
Workspace                   Runner         Suites      Tests Passed     Status
--------------------------------------------------------------------------------
@phishnetra/api (Express)   Jest           28          192 / 192        100% PASS
@phishnetra/extension (MV3) Jest            2           12 / 12        100% PASS
services/ml (FastAPI)       Pytest          8           58 / 58        100% PASS
--------------------------------------------------------------------------------
TOTAL MONOREPO TESTS                       38          262 / 262        100% PASS
================================================================================
Production Build Verification:
  • @phishnetra/shared:    CLEAN (tsc)
  • @phishnetra/api:       CLEAN (tsc)
  • @phishnetra/web:       CLEAN (tsc && vite build - 1610 modules transformed)
  • @phishnetra/extension: CLEAN (tsc && vite build - 1508 modules transformed)
================================================================================
```

---

## 12. Quickstart & Installation Guide

### Prerequisites
- **Node.js**: `v20.0.0` or higher
- **npm**: `v9.0.0` or higher
- **Python**: `v3.10.0` or higher

### Step 1: Clone & Install Dependencies
```bash
# Clone the repository
git clone https://github.com/Sidd-commits/PhishNetra.git
cd PhishNetra

# Install Node.js monorepo workspace dependencies
npm install

# Install Python ML microservice dependencies
pip install -r services/ml/requirements.txt
```

### Step 2: Configure Environment & Build Shared Packages
```bash
# Copy sample environment configuration
cp .env.example .env

# Build shared TypeScript types and schemas
npm run build:shared
```

### Step 3: Run the Monorepo Services
```bash
# Terminal 1: Python ML Microservice (Port 8000)
npm run dev:ml

# Terminal 2: Express Backend API (Port 5000)
npm run dev:api

# Terminal 3: React Web Security Console (Port 5173)
npm run dev:web

# Terminal 4: Chrome Extension Build (Outputs to apps/extension/dist)
npm run dev:extension
```

### Sideloading the Browser Extension (Chrome / Edge / Brave):
1. Navigate to `chrome://extensions/` in your browser.
2. Enable the **Developer mode** toggle in the top-right corner.
3. Click the **Load unpacked** button.
4. Select the directory: `PhishNetra/apps/extension/dist`.
5. The PhishNetra shield icon will appear in your browser toolbar with real-time protection active.

---

## 13. Live Demonstration Protocol (Evaluation Walkthrough)

Follow this 5-step sequence for an academic presentation or project evaluation:

1. **System Presentation & Research Context (1 min):**  
   Open `http://localhost:5173`. Explain why single-signal blacklists fail against modern fast-flux phishing campaigns and show the active Zero-Trust defense status.
2. **Live Multi-Layer URL Threat Scan (2 min):**  
   Navigate to `/analyze`. Submit the controlled suspicious fixture:  
   `http://secure-login-update-paypal-verification.com/account`  
   Demonstrate the 8-layer visual breakdown: domain registration age (<48h), high lexical Shannon entropy, Random Forest classification probability (0.94), and Tree-SHAP explainability findings.
3. **Email Attachment Link Extraction Vertical Slice (2 min):**  
   Navigate to `/attachments`. Select the pre-loaded **Urgent_Invoice_Overdue.pdf** preset. Demonstrate safe pure-JS hyperlink extraction, deduplication, and automated multi-layer analysis of extracted links without executing active code. Highlight the distinction between `THREATS_DETECTED` and `NO_SUSPICIOUS_URLS_FOUND`.
4. **Browser Extension Prototype & Interstitial Barrier (1.5 min):**  
   Navigate to `/extension`. Showcase the extension lifecycle diagram and click **Preview Interstitial Warning Overlay**. Demonstrate the un-bypassable DOM barrier freezing page interactions and presenting the 3 conscious user choices.
5. **Telemetry History & Semester 2 Roadmap (0.5 min):**  
   Navigate to `/history` to review the audit trail and show JSON export capability. Conclude with [`docs/ROADMAP.md`](docs/ROADMAP.md) detailing the Semester 2 empirical evaluation plan.

---

## 14. Two-Semester Academic Roadmap

| Milestone | Target | Focus Area | Status | Deliverables |
| :--- | :--- | :--- | :---: | :--- |
| **Semester 1: Core Prototype** | Months 1–5 | Multi-Layer Pipeline, Baseline ML, Attachment Link Slice, MV3 Extension Prototype, Academic UI | **VERIFIED** | 262 tests passing, demonstrable core workflow. |
| **Semester 2: Benchmark Evaluation** | Month 6 | Standard Benchmark Datasets (PhishTank, Alexa 1M, Mendeley); Precision/Recall/F1/AUC | **PLANNED** | Documented dataset splits and comparative metrics. |
| **Semester 2: Extension Hardening** | Month 7 | `chrome.declarativeNetRequest` dynamic rulesets to eliminate first-byte leakage; Firefox/Edge | **PLANNED** | True pre-navigation blocking & cross-browser support. |
| **Semester 2: Extended Formats** | Month 8 | OpenXML XLSX/PPTX, RTF link extraction; defanged link unmasking | **PLANNED** | Expanded corporate attachment coverage. |
| **Semester 2: Visual Brand Model** | Month 8 | Computer vision logo similarity (YOLO/CLIP) vs DOM attribute analysis | **PLANNED** | Anti-cloaking visual detection prototype. |
| **Semester 2: Calibration & Thesis** | Months 9–10 | Dynamic layer weight calibration; latency profiling; usability study; thesis dissertation | **PLANNED** | Academic project thesis report and final defense. |

---

## 15. Authoritative Documentation Index

- [`docs/SEMESTER_MILESTONE_AUDIT.md`](docs/SEMESTER_MILESTONE_AUDIT.md) — Definitive capability audit and technical verification matrix
- [`docs/PROJECT_SCOPE.md`](docs/PROJECT_SCOPE.md) — Official project scope & two-semester specifications
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — Comprehensive two-semester milestone roadmap
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System architecture (Semester 1 baseline vs Semester 2 evolution)
- [`docs/API.md`](docs/API.md) — REST API endpoint specification (in-scope vs deferred)
- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) — Implementation status report & build log
- [`docs/SECURITY.md`](docs/SECURITY.md) — Threat model, SSRF defenses, and Zero-Trust invariants

---

## 16. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
