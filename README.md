# PhishNetra 🛡️

> **A Multi-Layered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation**

[![Academic Milestone](https://img.shields.io/badge/Milestone-Semester%201%20Research%20Prototype-cyan.svg)](docs/SEMESTER_MILESTONE_AUDIT.md)
[![Tests Passing](https://img.shields.io/badge/Tests-262%2F262%20Passing%20(100%25)-brightgreen.svg)](tests/)
[![Node.js](https://img.shields.io/badge/Node.js-v20+-green.svg)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3+-61DAFB.svg)](https://react.dev/)
[![Chrome Extension](https://img.shields.io/badge/Extension-Manifest%20V3-orange.svg)](apps/extension/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 1. Project Overview & Academic Milestone

**PhishNetra** is a defense-in-depth cybersecurity framework engineered to replace reactive, static URL blacklists with real-time, explainable, multi-signal phishing detection. The project is an academic major project spanning a **ten-month, two-semester lifecycle**.

We are currently at the **Semester 1 Milestone Evaluation (Months 1–5)**. The codebase is organized into three distinct, verifiable categories:

1. **Implemented in Semester 1 (Working Prototype & Proof of Concept):**
   - Multi-layer Zero-Trust URL threat pipeline (lexical heuristics, domain RDAP age, DNS resolution, TLS certificate inspection, and threat reputation feeds).
   - Baseline Machine Learning classifier (scikit-learn Random Forest) operating on 18 deterministic features with Tree-SHAP explainability.
   - Email Attachment Link Extraction vertical slice safely parsing hyperlinks from `PDF`, `HTML`, `DOCX`, `TXT`, and `EML` without binary code execution.
   - Chrome Manifest V3 browser extension proof of concept providing sub-5ms local heuristics, dynamic toolbar badge signaling, and an un-bypassable DOM interstitial barrier overlay.
   - Academic research web console (`apps/web`) with live scanners, telemetry history, and JSON export.
2. **Semester 1 Prototypes (Partial Implementations):**
   - Sandboxed webpage DOM & brand mismatch analyzer (functional subset with SSRF protection; optional toggle).
   - Browser extension tab navigation monitoring (`tabs.onUpdated` hook).
3. **Planned for Semester 2 (Empirical Evaluation & Hardening Roadmap):**
   - Standard benchmark dataset evaluation (measuring precision, recall, F1, ROC-AUC on PhishTank, Alexa 1M benign set, and Mendeley).
   - Extension navigation lifecycle hardening via `chrome.declarativeNetRequest` to guarantee zero first-byte leakage.
   - Expanded attachment format support (OpenXML XLSX/PPTX, RTF) and redirect unmasking.
   - Dynamic layer weight calibration and latency profiling under concurrent load.

---

## 2. System Architecture (Semester 1 Baseline)

```text
                               ┌──────────────────────────────────────────────┐
                               │       Client & Endpoint Applications         │
                               └──────────────────────┬───────────────────────┘
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       │                                                             │
                       ▼                                                             ▼
         ┌───────────────────────────┐                                 ┌───────────────────────────┐
         │  apps/web (Research UI)   │                                 │ apps/extension (MV3 Ext)  │
         │   React 18 + Vite + TS    │                                 │ Local Heuristics & Barrier│
         └─────────────┬─────────────┘                                 └─────────────┬─────────────┘
                       │                                                             │
                       └──────────────────────────────┬──────────────────────────────┘
                                                      │ (HTTP/REST POST /api/analyze)
                                                      ▼
                                       ┌─────────────────────────────┐
                                       │   apps/api (Backend Core)   │
                                       │    Express + TS + Zod       │
                                       └──────────────┬──────────────┘
                                                      │
         ┌────────────────────────────────────────────┼────────────────────────────────────────────┐
         ▼                                            ▼                                            ▼
┌──────────────────────────┐             ┌──────────────────────────┐                 ┌──────────────────────────┐
│ services/ml (FastAPI)    │             │ Multi-Layer Risk Engine  │                 │ In-Memory LRU Cache      │
│ • Random Forest Classifier│             │ • Layer 1: Lexical (16)  │                 │ • Deterministic lookup   │
│ • 18 Lexical Features    │             │ • Layer 2: RDAP Age      │                 │ • Redis fallback         │
│ • Tree-SHAP Attribution  │             │ • Layer 3: DNS & Bogons  │                 │   (with offline fallback)│
│ • Sandboxed DOM Analyzer │             │ • Layer 4: TLS Certs     │                 │                          │
│   (SSRF Protected)       │             │ • Layer 5: Threat Feeds  │                 │                          │
└──────────────────────────┘             └──────────────────────────┘                 └──────────────────────────┘
```

---

## 3. Repository Directory Structure

```text
PhishNetra/
│
├── apps/
│   ├── api/                     # Node.js + Express + TypeScript Backend Core
│   │   ├── src/controllers/     # REST Controllers (Analysis, Attachment Ingest, Domains, Queue)
│   │   ├── src/services/        # Multi-Layer Zero-Trust Risk Engine & Attachment Parsers
│   │   │   ├── analysis/        # Canonicalization, DNS, TLS, RDAP, Lexical, SSRF utilities
│   │   │   └── ingestion/       # Safe pure-JS attachment hyperlink extraction (PDF/HTML/DOCX/TXT)
│   │   └── tests/               # 192 comprehensive Jest + Supertest suites (100% passing)
│   │
│   ├── web/                     # React 18 + Vite Academic Research Console
│   │   ├── src/pages/           # Live Scanner, Attachment Scanner, History, Extension Showcase
│   │   └── src/components/      # Multi-Layer Breakdown, Gauge, Evidence Tables
│   │
│   └── extension/               # Chrome Manifest V3 Browser Extension Prototype
│       ├── src/background/      # Service worker, local heuristics (<5ms), API client
│       ├── src/content/         # Content script DOM scanner & interstitial warning barrier
│       └── tests/               # 12 Jest unit tests passing
│
├── services/
│   └── ml/                      # Python 3.10 + FastAPI Machine Learning Microservice
│       ├── app/                 # Feature extraction, Random Forest inference, SHAP, SSRF defense
│       └── tests/               # 58 Pytest automated ML & SSRF test cases (100% passing)
│
├── packages/
│   └── shared/                  # Shared TypeScript types, Zod schemas, & constants
│
├── docs/                        # Complete technical documentation & milestone reports
│   ├── SEMESTER_MILESTONE_AUDIT.md # Authoritative capability audit & verification evidence
│   ├── PROJECT_SCOPE.md         # Official scope & two-semester specifications
│   ├── ROADMAP.md               # Two-semester academic roadmap & acceptance criteria
│   ├── ARCHITECTURE.md          # System architecture (current baseline vs planned evolution)
│   ├── API.md                   # REST API endpoint reference (in-scope vs deferred)
│   ├── IMPLEMENTATION_STATUS.md # Current verification report (262 tests passing)
│   └── SECURITY.md              # Zero-Trust invariants & vulnerability defenses
│
└── package.json                 # Monorepo workspaces & build orchestration
```

---

## 4. Quickstart Guide

### Prerequisites
- **Node.js**: `v20.0.0` or higher
- **npm**: `v9.0.0` or higher
- **Python**: `v3.10.0` or higher

### Step 1: Install Dependencies
```bash
# Install Node.js monorepo workspace dependencies
npm install

# Install Python ML microservice dependencies
pip install -r services/ml/requirements.txt
```

### Step 2: Build Shared Packages
```bash
npm run build:shared
```

### Step 3: Run the Monorepo Services
```bash
# Terminal 1: Python ML Microservice (Port 8000)
npm run dev:ml

# Terminal 2: Express Backend API (Port 5000)
npm run dev:api

# Terminal 3: React Web Console (Port 5173)
npm run dev:web

# Terminal 4: Chrome Extension Build (Outputs to apps/extension/dist)
npm run dev:extension
```

### Sideloading the Browser Extension (Chrome / Edge / Brave):
1. Navigate to `chrome://extensions/` in your browser.
2. Toggle on **Developer mode** (top-right corner).
3. Click **Load unpacked** and select the directory: `PhishNetra/apps/extension/dist`.
4. The PhishNetra shield icon will appear in your toolbar.

---

## 5. Primary Demonstration Walkthrough (Semester 1 Presentation)

Follow this 5-step sequence for the Semester 1 demonstration:

1. **Research Overview:** Navigate to `http://localhost:5173`. Point to the Semester 1 Research Prototype indicator and explain why single-signal blacklists fail against rapid phishing campaigns.
2. **Live Multi-Layer URL Threat Scan:**  
   Navigate to `/analyze`. Submit the controlled suspicious fixture:  
   `http://secure-login-update-paypal-verification.com/account`  
   Demonstrate the 8-layer visual breakdown: domain age (<48h), high lexical entropy, Random Forest ML probability (0.94), and Tree-SHAP explainability findings.
3. **Email Attachment Link Extraction Vertical Slice:**  
   Navigate to `/attachments`. Select the pre-loaded **Urgent_Invoice_Overdue.pdf** preset. Demonstrate safe pure-JS hyperlink extraction, deduplication, and automated multi-layer evaluation without code execution. Point out the clear distinction between clean attachments and threats detected.
4. **Browser Extension Prototype & Interstitial Barrier:**  
   Open `/extension` to showcase the extension architecture and click **Preview Interstitial Warning Overlay**. Demonstrate the un-bypassable DOM security barrier locking input and offering safe choices (Return to Safety / View Details / Bypass).
5. **Review Telemetry & Semester 2 Roadmap:**  
   Open `/history` to show the audit record and JSON export. Conclude with [`docs/ROADMAP.md`](docs/ROADMAP.md) detailing the Semester 2 empirical evaluation plan.

---

## 6. Testing & Quality Assurance

```bash
# Run all automated tests across all workspaces (Node.js + Python ML)
npm run test:all

# Run backend API test suites (192 tests across 28 suites)
npm run test:api

# Run browser extension test suites (12 tests across 2 suites)
npm run test:extension

# Run Python ML microservice test suites (58 tests across 8 suites)
npm run test:ml
```

### Verified Test Suite Baseline
- **Backend API Tests:** `192 / 192 PASSED` (100%)
- **Browser Extension Tests:** `12 / 12 PASSED` (100%)
- **Python ML Tests:** `58 / 58 PASSED` (100%)
- **Total Monorepo Automated Tests:** `262 / 262 PASSED (100% Pass Rate)`
- **Production Build Status:** Clean production builds across all 4 packages (`shared`, `api`, `web`, `extension`).

---

## 7. Zero-Trust Security Controls

1. **SSRF Immunity:** Pre-flight and socket-level IP filtering blocks loopback (`127.0.0.0/8`), private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and AWS/GCP cloud metadata (`169.254.169.254`). Alternative hex/octal IP notations are normalized prior to DNS resolution.
2. **Safe Attachment Parsing:** Attachments are parsed exclusively in-memory using declarative regular expressions and XML decoders; active content, macros, and native binaries are **never executed**.
3. **Fail-Safe Scoring:** Composite risk engine handles corrupted or NaN layer scores gracefully; unknown or failed signals receive `SUSPICIOUS` or `UNABLE_TO_ANALYZE` rather than defaulting to `SAFE`.
4. **Extension Privacy:** Minimal Manifest V3 permissions (`activeTab`, `storage`, `scripting`). Form inputs, passwords, and unrelated history are never monitored or recorded.

---

## 8. Two-Semester Academic Roadmap

| Milestone | Target | Focus Area | Status | Deliverables |
| :--- | :--- | :--- | :---: | :--- |
| **Semester 1: Core Prototype** | Months 1–5 | Multi-Layer Pipeline, Baseline ML, Attachment Link Slice, MV3 Extension Prototype, Academic UI | **VERIFIED** | 262 tests passing, demonstrable core workflow. |
| **Semester 2: Benchmark Evaluation** | Month 6 | Standard Benchmark Datasets (PhishTank, Alexa 1M, Mendeley); Precision/Recall/F1/AUC | **PLANNED** | Documented dataset splits and comparative metrics. |
| **Semester 2: Extension Hardening** | Month 7 | `chrome.declarativeNetRequest` dynamic rulesets to eliminate first-byte leakage; Firefox/Edge | **PLANNED** | True pre-navigation blocking & cross-browser support. |
| **Semester 2: Extended Formats** | Month 8 | OpenXML XLSX/PPTX, RTF link extraction; defanged link unmasking | **PLANNED** | Expanded corporate attachment coverage. |
| **Semester 2: Visual Brand Model** | Month 8 | Computer vision logo similarity (YOLO/CLIP) vs DOM attribute analysis | **PLANNED** | Anti-cloaking visual detection prototype. |
| **Semester 2: Calibration & Thesis** | Months 9–10 | Dynamic layer weight calibration; latency profiling; usability study; thesis dissertation | **PLANNED** | Academic project thesis report and final defense. |

---

## 9. Authoritative Documentation Index

- [`docs/SEMESTER_MILESTONE_AUDIT.md`](docs/SEMESTER_MILESTONE_AUDIT.md) — Definitive capability audit and technical verification matrix
- [`docs/PROJECT_SCOPE.md`](docs/PROJECT_SCOPE.md) — Official project scope & two-semester specifications
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — Comprehensive two-semester milestone roadmap
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System architecture (Semester 1 baseline vs Semester 2 evolution)
- [`docs/API.md`](docs/API.md) — REST API endpoint specification (in-scope vs deferred)
- [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) — Implementation status report & build log
- [`docs/SECURITY.md`](docs/SECURITY.md) — Threat model, SSRF defenses, and Zero-Trust invariants

---

## 10. License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
