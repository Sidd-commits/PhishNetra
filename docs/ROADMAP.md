# PhishNetra — Academic Master Roadmap & Implementation Alignment

**Official Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Time Allocation:** 10-Month Major Academic Project  
**Authoritative Scope Document:** [`docs/PROJECT_SCOPE.md`](PROJECT_SCOPE.md)  
**Detailed Audit Inventory:** [`docs/SCOPE_AUDIT.md`](SCOPE_AUDIT.md)  
**Upcoming Milestone:** Panel Presentation & Live Architecture Demonstration  

---

## 1. Executive Status Overview

PhishNetra addresses real-time web phishing detection and browser-level mitigation through a zero-trust, multi-layered architecture. Following a rigorous scope audit and refactoring, the project is structured around six core research and engineering questions:

1. **URL Evaluation:** Is the URL suspicious or malicious?
2. **Explainable Evidence:** What concrete evidence across DNS, TLS, domain age, and ML features supports the verdict?
3. **Webpage Indicators:** Does the rendered webpage exhibit credential-harvesting or brand-impersonation indicators invisible in the URL alone?
4. **Attachment Extraction:** Does an email attachment contain embedded URLs leading to phishing destinations?
5. **Real-Time Mitigation:** Can the browser extension communicate risk and block navigation with an interstitial barrier before user credentials are compromised?
6. **User Guidance:** What safe, actionable choices does the system provide to the user?

---

## 2. Master Roadmap & Milestone Classification

The table below reflects the **verified implementation status** across the 10-month development lifecycle:

| Phase / Milestone | Target Timeframe | Focus Area | Status | Deliverables & Verification |
| :--- | :--- | :--- | :---: | :--- |
| **Phase 1: Foundation & Baseline ML** | Months 1 → 2 | URL Canonicalization, Lexical Features, Random Forest Classifier, Core API & Web Console | **VERIFIED (CORE)** | `canonicalization.ts`, `services/ml/app/model/pipeline.py`, 58 Pytest tests passing. |
| **Phase 2: Multi-Layer Intelligence** | Months 3 → 4 | RDAP/WHOIS Domain Age, DNS Resolution, TLS Structural Checks, Blacklist Feeds & Zero-Trust Invariants | **VERIFIED (CORE)** | Multi-layer risk engine, `RiskEngineService.ts`, async layer parallelization with strict timeouts. |
| **Phase 3: Web Content & DOM Analysis** | Months 5 → 6 | SSRF-Protected Webpage Fetching, DOM Form Action Inspection, Cross-Origin Credential Traps, Brand Mismatch | **VERIFIED (CORE)** | Isolated DOM analyzer, SSRF loopback/private range protection, 26 unit tests. |
| **Phase 4: Async Batching & Domain Hub** | Months 6 → 7 | High-Capacity URL Queue, Domain Dossier, Typosquatting / Homoglyph Deception Detection | **VERIFIED (SUPPORTING)** | BullMQ/Redis worker pipeline, Levenshtein & Cyrillic confusables matrix (`typosquatting.ts`). |
| **Phase 5: Chrome Extension (Manifest V3)** | Months 7 → 8 | Real-Time Tab Navigation Interception, Local Heuristics, Multi-Tier API Client, DOM Interstitial Overlay | **VERIFIED (P0 PRIMARY)** | `apps/extension`, Chrome MV3 service worker, `interstitial.ts` zero silent redirects barrier. |
| **Phase 6: Email Attachment Link Analysis** | Months 8 → 9 | Safe Hyperlink Extraction from Supported Formats (PDF, HTML, DOCX, TXT, EML) & Multi-Layer Evaluation | **VERIFIED (P0 CORE)** | `AttachmentAnalysisService.ts`, pure-JS safe parser, `POST /api/ingest/attachment`, 10 automated tests. |
| **Phase 7: Explainable Risk & User Experience** | Months 9 → 10 | Telemetry History, Structured Evidence Engine, Simplified Academic UI, Developer Guides | **VERIFIED (P1 SUPPORTING)** | `AnalysisHistoryPage.tsx`, `ExtensionGuidePage.tsx`, clean 8-item navigation. |
| **Phase 8: Evaluation & Panel Presentation** | Presentation Target | Live End-to-End Walkthrough, Performance & Latency Benchmarks, False Positive Characterization | **ACTIVE / READY** | Complete automated test suite passing (262/262 tests, 100%), verified live daemons. |

---

## 3. Scope Boundaries & Deferred Features

During earlier development milestones, enterprise-oriented Security Operations Center (SOC) modules were implemented or mocked that exceeded the academic major project thesis. These modules have been **safely decoupled from active navigation** and classified as **DEFERRED** for future research:

```
+-----------------------------------------------------------------------------------------+
|                               PHISHNETRA REPOSITORY SCOPE                               |
|                                                                                         |
|  [P0 CORE — ACTIVE & TESTED]                [P1 SUPPORTING — ACTIVE & TESTED]           |
|  * Chrome Manifest V3 Browser Extension     * Web Dashboard Overview                    |
|  * Multi-Layer URL Threat Scanner           * Telemetry & Audit History                 |
|  * Email Attachment Hyperlink Analyzer      * Domain Intelligence Dossier               |
|  * Baseline Random Forest ML Model          * Async Batch Queue Ingestion               |
|  * Webpage Content & Form Analyzer          * Detection Settings & Calibration          |
|  * Zero-Trust Interstitial Overlay          * Extension Installation Guide              |
|                                                                                         |
|  [DEFERRED — REMOVED FROM ACTIVE UI / PRESERVED FOR FUTURE WORK]                        |
|  * SOAR Playbook Orchestrator               * Autonomous Incident Cases                 |
|  * Remote Browser Isolation (RBI) Sandbox   * Phishing Tarpit Flooder                   |
|  * STIX/TAXII 2.1 Threat Exchange           * BGP Route Integrity Radar                 |
|  * FIDO2 Credential Guard Admin             * Attack Surface Management (EASM)          |
|  * Telecom Vishing / STIR-SHAKEN Fusion     * Digital Forensics DPI & HAR Chaining      |
|  * Executive Board-Level Briefings          * Continuous Session Anomaly JA3 Drift      |
+-----------------------------------------------------------------------------------------+
```

---

## 4. Test & Verification Baseline

| Test Suite / Target | Number of Tests | Status | Execution Command |
| :--- | :---: | :---: | :--- |
| **`@phishnetra/api` (Backend Express)** | **192 tests** (28 suites) | **100% PASS** | `npm test --workspace=@phishnetra/api` |
| **`@phishnetra/extension` (Browser MV3)** | **12 tests** (2 suites) | **100% PASS** | `npm test --workspace=@phishnetra/extension` |
| **`services/ml` (Python FastAPI)** | **58 tests** | **100% PASS** | `pytest services/ml/tests` |
| **Total Monorepo Automated Tests** | **262 tests** | **100% PASS** | Zero regressions monorepo-wide |
| **Production Build Status** | All Packages | **CLEAN** | `npm run build` (Shared, API, Web, Extension) |

---

## 5. Remaining Academic Milestones (Pre-Final Evaluation)

- [x] Master Scope Correction and Repository Audit (`docs/SCOPE_AUDIT.md`, `docs/PROJECT_SCOPE.md`).
- [x] Email Attachment Link Analysis implementation (`AttachmentAnalysisService.ts`).
- [x] Pure-JS multi-format link extraction (PDF, HTML, DOCX, TXT, EML) with strict safety boundaries.
- [x] Restructure Web Navigation and Dashboard to emphasize the Extension and Core Scanners.
- [x] Create dedicated Chrome Extension Showcase and Installation Guide (`/extension`).
- [x] Build comprehensive telemetry history viewer (`/history`).
- [ ] Conduct live panel presentation and walkthrough (3-day target).
- [ ] Finalize academic project thesis document and performance benchmark chapter.
