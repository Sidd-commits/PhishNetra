# PhishNetra 🛡️

> **A Multi-Layered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation**

[![Academic Classification](https://img.shields.io/badge/Academic%20Project-Two--Semester%20Major%20Project-cyan.svg)](docs/PROJECT_SCOPE.md)
[![Milestone](https://img.shields.io/badge/Milestone-Semester%201%20Deliverable%20Verified-blue.svg)](docs/SEMESTER_MILESTONE_AUDIT.md)
[![Automated Tests](https://img.shields.io/badge/Tests-285%2F285%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![Node.js](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Chrome Extension](https://img.shields.io/badge/Extension-Manifest%20V3-orange.svg)](apps/extension/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Executive Summary & Academic Project Abstract

**PhishNetra** is an integrated cybersecurity research and engineering framework designed to address the systemic vulnerabilities of conventional phishing defenses. Traditional threat detection mechanisms rely predominantly on static URL blacklists, reputation feeds, and post-incident crowdsourced reporting. In modern adversary campaigns, these reactive defenses fail due to three critical attack innovations:

1. **Ephemeral Infrastructure & Fast-Flux DNS:** Attackers register disposable lookalike domains that operate for only a few hours before migrating IP addresses, rendering static blacklists ineffective due to multi-hour or multi-day indexing dwell times.
2. **Subtle Lexical & Homoglyph Evasions:** Internationalized Domain Names (IDNs) and lookalike Unicode substitutions (e.g., Cyrillic homoglyphs) visually mimic legitimate brand domains while resolving to malicious server infrastructure.
3. **Evasive Delivery Vectors (Attachment Phishing):** Adversaries increasingly embed credential-harvesting hyperlinks within innocent-looking email attachments (PDF invoices, HTML verification notices, DOCX manifests, plain-text security alerts) to bypass standard mail gateway URL filters.

To solve these challenges, PhishNetra introduces a **Zero-Trust evaluation model**: *no destination is trusted based on a single benign signal*. A website with an active, valid TLS certificate from a trusted authority is not classified as safe if its domain registration age is less than 48 hours, its lexical entropy indicates algorithmic randomness, its form actions transmit credentials to an external server, or its layout mimics an enterprise brand catalog.

PhishNetra combines:
- An **8-Layer Zero-Trust Threat Analysis Pipeline** operating on normalized destination targets.
- A **Calibrated Baseline Machine Learning Classifier** (Random Forest, sub-5ms latency) equipped with **Tree-SHAP explainability** to expose feature-level attribution.
- A **Safe Email Attachment Link Extraction Engine** that parses document streams in memory without code execution.
- A **Chrome Manifest V3 Browser Extension** providing instantaneous client-side heuristic scoring and an **un-bypassable DOM security barrier overlay** (`interstitial.ts`).
- An **Academic Web Security Console** providing SOC analysts and academic evaluators with live scanning, telemetry history, domain dossier investigations, and queue processing.

---

## 2. Academic Project Scope & Two-Semester Lifecycle

PhishNetra is developed as a **two-semester academic major project spanning approximately ten months**. To maintain strict scientific integrity and defensibility before academic review panels, the project roadmap replaces all commercial enterprise sprint models with a clear, honest academic milestone division:

```
+---------------------------------------------------------------------------------------------------+
|                               PHISHNETRA TWO-SEMESTER TIMELINE                                     |
+---------------------------------------------------------------------------------------------------+
|  SEMESTER 1 (Months 1 → 5): Core Research Prototype & Proof of Concept [DELIVERED & VERIFIED]    |
|  • Multi-Layer Zero-Trust URL Threat Pipeline (Canonicalization, Lexical, RDAP, DNS, TLS, Feeds)    |
|  • Calibrated Baseline Machine Learning Classifier (Random Forest + Tree-SHAP Explainability)     |
|  • Email Attachment Link Extraction Engine (Pure-JS Safe Parsers: PDF, HTML, DOCX, TXT, EML)     |
|  • Chrome Manifest V3 Browser Extension Prototype (Sub-5ms Heuristics + DOM Interstitial Barrier) |
|  • Unified Academic Security Console (React 18 + Vite Dashboard, Scanners, Telemetry History)     |
|  VERIFICATION: 285/285 Automated Tests Passing (100%) • 4/4 Workspaces Clean Production Builds    |
+---------------------------------------------------------------------------------------------------+
|  SEMESTER 2 (Months 6 → 10): Empirical Evaluation, Hardening & Academic Thesis [PLANNED ROADMAP] |
|  • Benchmark Dataset Evaluation (Precision, Recall, F1, ROC-AUC on PhishTank, Alexa Top 1M)      |
|  • Extension Lifecycle Hardening (chrome.declarativeNetRequest Dynamic Rulesets, Zero Leakage)   |
|  • Extended File Ingestion Coverage (OpenXML XLSX/PPTX, RTF, Multi-Hop Redirect Chain Unmasking)   |
|  • Computer Vision Logo Similarity Prototype (YOLO/CLIP Visual Brand Matching vs DOM Forms)       |
|  • Dynamic Layer Weight Calibration via Validation Loss & End-to-End Latency Benchmarking        |
|  • Academic Project Thesis Dissertation, Warning Compliance Usability Study, and Final Defense     |
+---------------------------------------------------------------------------------------------------+
```

### Scope Boundary & Enterprise Module Deferral
Earlier exploratory development produced draft enterprise concepts (e.g., Autonomous SOAR Playbooks, Remote Browser Isolation (RBI), TAXII 2.1 Threat Exchange, BGP Route Hijack Radar, and FIDO2 Admin). While backend routes and tests for these capabilities remain preserved in the codebase for architectural continuity, **they are explicitly excluded from the academic evaluation scope** to keep the research tightly focused on client-side and endpoint phishing mitigation.

---

## 3. Research Questions & Engineering Objectives

PhishNetra systematically investigates six core research and engineering questions:

| # | Research / Engineering Question | Methodological Resolution in PhishNetra |
| :-: | :--- | :--- |
| **RQ1** | **Can multi-signal inspection detect phishing URLs that bypass single-signal blacklists?** | Implemented through an 8-layer parallel analysis engine evaluating lexical structures, RDAP registration age, passive DNS anomalies, TLS certificates, and brand catalog mismatches. |
| **RQ2** | **How can machine learning predictions be made explainable to non-expert users and SOC analysts?** | Integrated Tree-SHAP (SHapley Additive exPlanations) alongside a Random Forest classifier to compute deterministic feature impact scores and synthesize natural-language rationales. |
| **RQ3** | **How can hidden phishing hyperlinks inside email attachments be analyzed safely without triggering malware execution?** | Developed in-memory, pure-JavaScript regular expression and XML stream decoders for PDF, HTML, DOCX, TXT, and EML files with a 10MB limit and zero code execution. |
| **RQ4** | **Can real-time browser-level protection be achieved under Google Chrome's Manifest V3 constraints?** | Engineered a two-tier defense: sub-5ms client-side heuristics in the background service worker, coupled with asynchronous API lookups and proactive `CHECK_PAGE_THREAT` messaging. |
| **RQ5** | **How can dangerous credential theft be halted without violating user agency?** | Implemented an un-bypassable DOM Interstitial Barrier overlay (`interstitial.ts`, `z-index: 2147483647`) that freezes interaction and mandates a conscious choice: *Return to Safety*, *Inspect SOC Evidence*, or *Conscious Bypass*. |
| **RQ6** | **How can server infrastructure remain immune to adversarial SSRF and DNS rebinding attacks?** | Enforced pre-flight IP socket filtering blocking private subnets (RFC 1918), loopback, link-local, cloud instance metadata (`169.254.169.254`), and capped redirect chains at 5 hops. |

---

## 4. Operational System Architecture

All inputs—whether submitted via the interactive Web Console, the Chrome extension, the bulk batch queue, or file uploads—traverse a unified evaluation lifecycle:

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
         │ • Live URL Threat Scanner   │                                       │ • Sub-5ms Local Heuristics  │
         │ • Attachment Link Scanner   │                                       │ • CHECK_PAGE_THREAT Query   │
         │ • Domain Dossier & Typos    │                                       │ • DOM Interstitial Barrier  │
         │ • Batch Processing & History│                                       │   (z-index: 2147483647)     │
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

## 5. Repository Monorepo Structure

```text
PhishNetra/
│
├── apps/
│   ├── api/                          # Node.js + Express + TypeScript Backend Core
│   │   ├── src/controllers/          # REST Endpoints (Analyze, Ingest, Domains, Queue, Auth, Reports)
│   │   ├── src/services/             # Threat Pipeline & Ingestion Services
│   │   │   ├── analysis/             # Canonicalization, Lexical, DNS, TLS, RDAP, Reputation, Typos
│   │   │   ├── ingestion/            # Safe pure-JS attachment link extraction (PDF/HTML/DOCX/TXT/EML)
│   │   │   ├── queue/                # BullMQ asynchronous batch job queue worker
│   │   │   └── risk/                 # Zero-Trust Risk Engine & Tree-SHAP Evidence Synthesizer
│   │   └── tests/                    # 192 Jest automated unit/integration tests (100% passing)
│   │
│   ├── web/                          # React 18 + Vite + Tailwind CSS Security Console
│   │   ├── src/pages/                # Dashboard, Analyze, Attachments, Domains, Batch, History, Settings
│   │   ├── src/components/           # Navbar, Risk Gauge, Multi-Layer Breakdown, Interstitial Modal
│   │   └── src/services/             # Axios API client with token & API-key authentication
│   │
│   └── extension/                    # Chrome Manifest V3 Browser Extension
│       ├── src/background/           # Service worker, sub-5ms local heuristics, badge manager, tab state
│       ├── src/content/              # Content script, un-bypassable DOM interstitial barrier, banner
│       ├── src/popup/                # Extension toolbar popup UI, live tab inspection, whitelist toggle
│       └── tests/                    # 12 Jest unit tests for local heuristics & storage (100% passing)
│
├── services/
│   └── ml/                           # Python 3.10 + FastAPI Machine Learning Microservice
│       ├── app/api/                  # REST Endpoints (/predict, /analyze-page, /explain, /health)
│       ├── app/model/                # Calibrated Random Forest pipeline, registry, Tree-SHAP explainer
│       ├── app/features/             # Deterministic 18-feature lexical extractor
│       ├── app/analyzer/             # Webpage DOM fetcher with strict SSRF and redirect defenses
│       └── tests/                    # 58 Pytest automated ML & SSRF test cases (100% passing)
│
├── packages/
│   └── shared/                       # Shared TypeScript definitions, Zod validation schemas, & constants
│
├── docs/                             # Authoritative Academic Documentation Index
│   ├── SEMESTER_MILESTONE_AUDIT.md   # Definitive capability audit & technical verification evidence
│   ├── PROJECT_SCOPE.md              # Official scope & two-semester specifications
│   ├── ROADMAP.md                    # Two-semester academic roadmap & acceptance criteria
│   ├── ARCHITECTURE.md               # System architecture (current baseline vs planned evolution)
│   ├── API.md                        # REST API endpoint reference
│   ├── IMPLEMENTATION_STATUS.md      # Monorepo build and test verification report
│   └── SECURITY.md                   # Zero-Trust invariants & vulnerability defenses
│
├── prisma/
│   └── schema.prisma                 # Database schema (Analyses, Evidences, BatchJobs, Users, Reports)
│
├── package.json                      # Monorepo workspaces & build orchestration scripts
└── LICENSE                           # MIT License
```

---

## 6. The Multi-Layer Zero-Trust Threat Engine (8 Layers)

PhishNetra enforces a non-negotiable Zero-Trust invariant: **no single signal determines safety**. Each incoming URL is evaluated across eight distinct structural, infrastructural, and behavioral layers:

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

### Risk Engine Mathematical Formulation
The composite risk score $S \in [0, 100]$ is computed as a normalized weighted sum of active layer scores:

$$S = \frac{\sum_{i=1}^{n} w_i \cdot s_i}{\sum_{i=1}^{n} w_i}$$

Where:
- $w_i \ge 0$ is the configurable weight for layer $i$.
- $s_i \in [0, 100]$ is the raw risk score output by layer $i$.
- If an upstream layer fails or encounters a network timeout, its weight is gracefully excluded from the denominator to prevent score corruption or NaN propagation.

### Verdict Tiers & Zero-Trust Overrides
- **SAFE (Score: 0 – 39):** Minimal threat indicators detected.
- **SUSPICIOUS (Score: 40 – 69):** Elevated anomaly score (e.g., brand keyword in path + novel domain age).
- **PHISHING (Score: 70 – 100):** High-confidence threat detected.
- **Deterministic Overrides:**
  - If Layer 5 (Reputation) confirms an active blocklist hit $\implies S = 100$, Verdict = **PHISHING**.
  - If Layer 2 (RDAP) detects registration age $< 48$ hours with brand lures $\implies S \ge 85$, Verdict = **PHISHING**.

---

## 7. Baseline Machine Learning & Tree-SHAP Explainability

### Model Specifications
- **Algorithm:** Calibrated Random Forest Classifier (`scikit-learn`, 100 estimators, max depth 12).
- **Execution Tier:** Python 3.10 + FastAPI microservice (`services/ml`) operating on `http://127.0.0.1:8000`.
- **Inference Latency:** Sub-5ms per URL.
- **Explainability:** Integrated Tree-SHAP (`shap.TreeExplainer`) provides exact Shapley values to compute positive and negative feature contributions.

### Deterministic 18-Feature Vector

| # | Feature Name | Description & Threat Significance |
| :-: | :--- | :--- |
| 1 | `url_length` | Total character count of normalized URL (phishing URLs frequently exceed 75 chars). |
| 2 | `hostname_length` | Length of fully qualified domain name (flags lengthy subdomains). |
| 3 | `path_length` | Character length of the URL path component. |
| 4 | `count_dots` | Total count of period delimiters (`.`) (flags excessive subdomain nesting). |
| 5 | `count_hyphens` | Frequency of hyphens (`-`) (commonly used in brand combosquatting, e.g., `paypal-verify`). |
| 6 | `count_at` | Presence of userinfo credential delimiter (`@`) used to mask true destinations. |
| 7 | `count_question` | Count of query parameters (`?`). |
| 8 | `count_percent` | Count of percent-encoded characters (`%`) indicative of obfuscation. |
| 9 | `count_digits` | Total numeric digit count in URL. |
| 10 | `count_subdomains` | Depth of subdomain labels excluding TLD and `www`. |
| 11 | `has_ip` | Binary flag (0 or 1) indicating raw IPv4 address used as hostname. |
| 12 | `shannon_entropy` | Information entropy of hostname string: $H(X) = -\sum P(x) \log_2 P(x)$ (measures randomness). |
| 13 | `is_punycode` | Detection of `xn--` internationalized homoglyph encoding. |
| 14 | `suspicious_tld` | Match against known high-abuse top-level domains (`.xyz`, `.top`, `.click`, `.buzz`, etc.). |
| 15 | `brand_keyword_count` | Frequency of sensitive brand keywords (e.g., `paypal`, `microsoft`, `apple`, `google`). |
| 16 | `has_sensitive_keyword`| Binary flag indicating presence of security credential lures (`login`, `verify`, `billing`). |
| 17 | `non_standard_port` | Detection of non-default HTTP/HTTPS ports (e.g., `:8080`, `:8888`, `:4444`). |
| 18 | `path_depth` | Number of slash delimiters in the URL path. |

---

## 8. Safe Email Attachment Link Extraction Engine

### The Evasive Attack Vector
To bypass standard secure email gateways, adversaries frequently embed phishing hyperlinks inside business documents. PhishNetra provides a safe, pure-JavaScript link extraction pipeline that unpacks supported formats in memory:

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
- **Declarative Non-Executable Parsing:** Relies on regular expressions and stream decoders. **Macros, active content, and shell scripts are never executed.**
- **Academic Scope Disclaimer:** PhishNetra evaluates embedded hyperlinks and target destination indicators. It does **not** constitute an operating-system sandbox or binary executable malware scanner.

---

## 9. Chrome Manifest V3 Browser Extension

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

## 10. Academic Web Security Console (`apps/web`)

The frontend is a fast, responsive Single Page Application built with **React 18 + Vite + TypeScript + Tailwind CSS**:

| Page / Route | Primary Capabilities |
| :--- | :--- |
| **Dashboard** ([`/dashboard`](http://localhost:5173/dashboard)) | Live telemetry overview, threat counters, active Zero-Trust defense status bar, recent analysis audit log. |
| **URL Threat Scanner** ([`/analyze`](http://localhost:5173/analyze)) | Interactive URL evaluation with 8-layer breakdown, risk gauge, SHAP narrative, and raw feature viewer. |
| **Attachment Scanner** ([`/attachments`](http://localhost:5173/attachments)) | Drag-and-drop file upload, 4 demo presets (PDF, HTML, DOCX, TXT), extracted link breakdown table. |
| **Domain Dossier Hub** ([`/domains`](http://localhost:5173/domains)) | RDAP registration age timeline, nameservers, MX records, lookalike typosquatting generator. |
| **Batch URL Scanner** ([`/batch`](http://localhost:5173/batch)) | Bulk URL list submission, asynchronous BullMQ worker processing, progress bar, CSV/JSON export. |
| **Telemetry History** ([`/history`](http://localhost:5173/history)) | Searchable, filterable audit log of evaluated targets with pagination, deep links, and JSON export. |
| **Extension Showcase** ([`/extension`](http://localhost:5173/extension)) | Visual extension lifecycle diagram, developer setup steps, interactive warning modal preview. |
| **System Settings** ([`/settings`](http://localhost:5173/settings)) | Dynamic risk layer weights, risk thresholds, provider toggles (URLhaus, PhishTank), API key generation. |

---

## 11. Zero-Trust Security Controls & Invariants

| Threat Vector | Mitigation Strategy & Verification |
| :--- | :--- |
| **Server-Side Request Forgery (SSRF)** | Pre-flight DNS resolution and socket-level filtering block loopback (`127.0.0.0/8`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and AWS/GCP cloud metadata (`169.254.169.254`). Alternative hex/octal IP notations are normalized prior to resolution (verified by 26 automated tests). |
| **DNS Rebinding (TOCTOU)** | Target hostname is resolved immediately prior to TCP handshake; aborts if resolved destination points to an internal boundary. |
| **Redirect Hop Pivoting** | Each redirect hop (`301`, `302`, `307`, `308`) is re-checked against the SSRF engine. Hard cap of 5 hops maximum. |
| **Attachment Code Execution** | Files are parsed in memory using declarative string decoders and regular expressions. Macros, active scripts, and binary payloads are never executed. |
| **Fail-Safe Principle** | Missing upstream intelligence or timeouts never default to a `SAFE` verdict. Unknown or failed signals receive `SUSPICIOUS` or `UNABLE_TO_ANALYZE`. |

---

## 12. Verification & Test Suite Baseline

```
================================================================================
                    PHISHNETRA MONOREPO VERIFICATION BASELINE
================================================================================
Workspace                   Runner         Suites      Tests Passed     Status
--------------------------------------------------------------------------------
@phishnetra/api (Express)   Jest           29          204 / 204        100% PASS
@phishnetra/extension (MV3) Jest            2           12 / 12        100% PASS
services/ml (FastAPI)       Pytest          9           69 / 69        100% PASS
--------------------------------------------------------------------------------
TOTAL MONOREPO TESTS                       40          285 / 285        100% PASS
================================================================================
Production Build Verification:
  • @phishnetra/shared:    CLEAN (tsc)
  • @phishnetra/api:       CLEAN (tsc)
  • @phishnetra/web:       CLEAN (tsc && vite build - 1610 modules transformed)
  • @phishnetra/extension: CLEAN (tsc && vite build - 1519 modules transformed)
================================================================================
```

### Running Test Suites
```bash
# Run all tests across the monorepo (Node.js + Python ML)
npm run test:all

# Run backend API suites (204 tests across 29 suites)
npm run test:api

# Run browser extension unit suites (12 tests across 2 suites)
npm run test:extension

# Run Python ML test suites (69 tests across 9 suites)
npm run test:ml
```

---

## 13. Quickstart & Installation Guide

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

## 14. Live Demonstration Protocol (Evaluation Walkthrough)

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

## 15. Two-Semester Academic Roadmap

The project progression adheres to the following two-semester milestone schedule:

| Milestone | Target | Focus Area | Status | Deliverables |
| :--- | :--- | :--- | :---: | :--- |
| **Semester 1: Core Prototype** | Months 1–5 | Multi-Layer Pipeline, Baseline ML, Attachment Link Slice, MV3 Extension Prototype, Academic UI | **VERIFIED** | 285 tests passing, demonstrable core workflow. |
| **Semester 2: Benchmark Evaluation** | Month 6 | Standard Benchmark Datasets (PhishTank, Alexa 1M, Mendeley); Precision/Recall/F1/AUC | **PLANNED** | Documented dataset splits and comparative metrics. |
| **Semester 2: Extension Hardening** | Month 7 | `chrome.declarativeNetRequest` dynamic rulesets to eliminate first-byte leakage; Firefox/Edge | **PLANNED** | True pre-navigation blocking & cross-browser support. |
| **Semester 2: Extended Formats** | Month 8 | OpenXML XLSX/PPTX, RTF link extraction; defanged link unmasking | **PLANNED** | Expanded corporate attachment coverage. |
| **Semester 2: Visual Brand Model** | Month 8 | Computer vision logo similarity (YOLO/CLIP) vs DOM attribute analysis | **PLANNED** | Anti-cloaking visual detection prototype. |
| **Semester 2: Calibration & Thesis** | Months 9–10 | Dynamic layer weight calibration; latency profiling; usability study; thesis dissertation | **PLANNED** | Academic project thesis report and final defense. |

---

## 16. Authoritative Documentation Index

All technical specifications, evaluation audits, and architecture decisions are documented in the [`docs/`](docs/) directory:

- [`docs/SEMESTER_MILESTONE_AUDIT.md`](docs/SEMESTER_MILESTONE_AUDIT.md) — Definitive capability audit and technical verification matrix
- [`docs/PROJECT_SCOPE.md`](docs/PROJECT_SCOPE.md) — Official project scope & two-semester specifications
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — Comprehensive two-semester milestone roadmap
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System architecture (Semester 1 baseline vs Semester 2 evolution)
- [`docs/API.md`](docs/API.md) — REST API endpoint specification
- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) — Monorepo build and test verification report
- [`docs/SECURITY.md`](docs/SECURITY.md) — Threat model, SSRF defenses, and Zero-Trust invariants

---

## 17. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
