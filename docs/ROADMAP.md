# PhishNetra — Two-Semester Academic Development Roadmap

**Official Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Time Allocation:** 10-Month Major Academic Project (Two Semesters)  
**Current Milestone:** Semester 1 Presentation & Milestone Evaluation (Months 1–5)  
**Authoritative Scope Document:** [`docs/PROJECT_SCOPE.md`](PROJECT_SCOPE.md)  
**Milestone Audit Evidence:** [`docs/SEMESTER_MILESTONE_AUDIT.md`](SEMESTER_MILESTONE_AUDIT.md)  

---

## 1. Academic Milestone Framework

PhishNetra is engineered across two structured academic semesters spanning ten months. The milestone roadmap below replaces all legacy sprint tracking to establish an honest, verifiable division between the **Semester 1 Deliverable (Working Prototype & Proof of Concept)** and the **Semester 2 Scope (Empirical Evaluation, Browser Hardening & Research Completion)**.

```
+---------------------------------------------------------------------------------------------------+
|                               PHISHNETRA TWO-SEMESTER TIMELINE                                     |
+---------------------------------------------------------------------------------------------------+
|  SEMESTER 1: Months 1 → 5 (Current Milestone)                                                     |
|  * Multi-Layer URL Threat Engine (Canonicalization, Lexical, Domain, DNS, TLS, Reputation)        |
|  * Baseline Random Forest ML Model with SHAP Feature Explainability                               |
|  * Email Attachment Link Extraction Vertical Slice (PDF, HTML, DOCX, TXT, EML)                     |
|  * Chrome Manifest V3 Extension Proof of Concept (Local Heuristics, Interstitial Barrier)         |
|  * Academic Research Dashboard & Telemetry Audit History                                          |
|  STATUS: VERIFIED & DEMONSTRABLE (262/262 Tests Passing)                                          |
+---------------------------------------------------------------------------------------------------+
|  SEMESTER 2: Months 6 → 10 (Future Development Roadmap)                                           |
|  * Standardized Benchmark Dataset Evaluation (Precision, Recall, F1, ROC-AUC)                      |
|  * Browser Extension Lifecycle Hardening (declarativeNetRequest, Zero First-Byte Leakage)         |
|  * Extended Attachment Coverage (OpenXML XLSX/PPTX, Obfuscated Redirect Tracking)                 |
|  * Computer Vision Brand Logo Matching Prototype (YOLO/CLIP vs DOM Inspection)                    |
|  * Dynamic Layer Weight Calibration & Latency Profiling under Load                                |
|  * Academic Thesis, Empirical Results Documentation & Final Defense                               |
|  STATUS: PLANNED ROADMAP                                                                          |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Semester 1 Milestones (Months 1–5): Working Prototype

| Milestone | Target | Description | Status | Verification & Deliverables |
| :--- | :--- | :--- | :---: | :--- |
| **S1.1: URL Canonicalization & Lexical Features** | Month 1 | RFC 3986 normalization, Punycode/IDN decoding, Shannon entropy, token depth, IP literal detection. | **VERIFIED** | `canonicalization.ts`, `urlLayer.ts`, 5 unit tests passing. |
| **S1.2: Baseline Machine Learning Model** | Month 2 | Scikit-learn Random Forest classifier trained on 18 lexical features; Tree-SHAP feature attribution. | **VERIFIED** | `services/ml/app/model/pipeline.py`, 58 Pytest tests passing. |
| **S1.3: Multi-Layer Threat Intelligence** | Month 3 | Parallel RDAP domain age, DNS resolution, TLS certificate checks, blacklist lookups with fail-safe NaN scoring. | **VERIFIED** | `RiskEngineService.ts`, `domainLayer.ts`, `dnsLayer.ts`, `tlsLayer.ts`. |
| **S1.4: Sandboxed Webpage DOM Analysis** | Month 4 | SSRF-protected remote fetching, form action check, cross-origin password target, 15-brand domain mismatch. | **PROTOTYPE** | `services/ml/app/analyzer/dom_parser.py`, 26 SSRF tests passing. |
| **S1.5: Email Attachment Link Extraction** | Month 4 | Safe pure-JS hyperlink extraction from PDF, HTML, DOCX, TXT, EML; 10MB ceiling; multi-layer evaluation. | **VERIFIED** | `AttachmentAnalysisService.ts`, `POST /api/ingest/attachment`, 10 tests passing. |
| **S1.6: Chrome Browser Extension (MV3)** | Month 5 | Background navigation monitoring (`tabs.onUpdated`), sub-5ms local heuristics, DOM interstitial barrier overlay. | **PROTOTYPE** | `apps/extension`, `interstitial.ts`, 12 Jest tests passing. |
| **S1.7: Academic Research Dashboard** | Month 5 | Streamlined web console: URL Threat Scanner, Attachment Scanner, Telemetry History with search/export. | **VERIFIED** | `apps/web/src/pages/`, clean 8-item navigation, zero dead routes. |
| **S1.8: Semester 1 Presentation** | Current | Live end-to-end demonstration, reproducible evaluation script, architecture defense before academic panel. | **ACTIVE** | All daemons verified, 262/262 tests passing, production builds clean. |

---

## 3. Semester 2 Milestones (Months 6–10): Empirical Evaluation & Hardening

| Milestone | Target | Focus Area | Acceptance Criteria & Technical Work | Status |
| :--- | :--- | :--- | :--- | :---: |
| **S2.1: Dataset Benchmarking & Metrics** | Month 6 | Evaluation Methodology | Curate standard benchmark datasets (PhishTank, Alexa Top 1M benign, Mendeley). Measure accuracy, precision, recall, F1-score, and ROC-AUC. Compare multi-layer against baseline single signals. | **PLANNED** |
| **S2.2: Extension Lifecycle Hardening** | Month 7 | Browser Protection | Migrate from `tabs.onUpdated` DOM injection to `chrome.declarativeNetRequest` dynamic rulesets to eliminate first-byte leakage before analysis completes. Add cross-browser support (Firefox, Edge). | **PLANNED** |
| **S2.3: Attachment Format Expansion** | Month 8 | Ingestion Pipeline | Implement safe hyperlink parsing for OpenXML XLSX/PPTX, RTF, and nested archives. Resolve shortened and multi-hop redirect chains within attachment URLs. | **PLANNED** |
| **S2.4: Visual Brand & Content Prototype** | Month 8 | Content Intelligence | Prototype computer vision logo similarity matching (YOLO/CLIP) to complement DOM attribute analysis. Evaluate anti-cloaking defenses against bot-detection evasions. | **PLANNED** |
| **S2.5: Dynamic Calibration & Optimization** | Month 9 | System Optimization | Optimize layer weighting using empirical validation loss. Profile end-to-end latency distributions and evaluate throughput under concurrent load. | **PLANNED** |
| **S2.6: Academic Thesis & Final Defense** | Month 10 | Final Evaluation | Complete academic thesis dissertation, document threats to validity, conduct usability study on warning interstitial compliance, and present final project defense. | **PLANNED** |

---

## 4. Scope Classification Matrix

```
+-----------------------------------------------------------------------------------------+
|                               PHISHNETRA REPOSITORY SCOPE                               |
|                                                                                         |
|  [SEMESTER 1 — VERIFIED DELIVERABLE]        [SEMESTER 2 — RESEARCH ROADMAP]             |
|  * Multi-Layer URL Threat Pipeline          * Standardized Benchmark Evaluation         |
|  * Baseline Random Forest ML Model          * declarativeNetRequest Hardening          |
|  * SHAP Tree Feature Explainability         * OpenXML XLSX/PPTX Attachment Support      |
|  * Attachment Link Extraction Slice         * Computer Vision Logo Similarity           |
|  * Chrome MV3 Extension Proof of Concept    * Dynamic Layer Weight Calibration          |
|  * Interstitial DOM Security Barrier        * Cross-Browser Compatibility (Firefox/Edge)|
|  * Academic Research Dashboard              * Comprehensive Thesis & Usability Study    |
|                                                                                         |
|  [EXPLICITLY DEFERRED — PRESERVED IN CODEBASE / EXCLUDED FROM THESIS SCOPE]             |
|  * Autonomous SOAR Playbook Containment     * SOC Incident Case Management Workbench    |
|  * Remote Browser Isolation (RBI) Sandbox   * Phishing Tarpit Credential Flooder        |
|  * STIX/TAXII 2.1 Threat Exchange           * BGP Route Integrity Radar                 |
|  * FIDO2 / WebAuthn Administration          * External Attack Surface Management (EASM) |
|  * Telecom Vishing / STIR-SHAKEN Fusion     * Board-Level Executive Risk Briefings      |
+-----------------------------------------------------------------------------------------+
```

---

## 5. Verification Baseline

- **Automated Tests:** 262 / 262 tests passing (100% pass rate)
  - Backend API: 192 tests (28 suites)
  - Browser Extension: 12 tests (2 suites)
  - ML Microservice: 58 tests (8 suites)
- **Production Builds:** 4/4 packages compile cleanly (`@phishnetra/shared`, `@phishnetra/api`, `@phishnetra/web`, `@phishnetra/extension`)
- **Active Daemons:** Python ML (`:8000`), Express API (`:5000`), React Web (`:5173`)
