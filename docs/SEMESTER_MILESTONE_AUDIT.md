# PhishNetra — Semester Milestone Audit & Technical Verification

**Official Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Project Classification:** 10-Month Major Academic Project (Two-Semester Lifecycle)  
**Evaluation Target:** Semester 1 Presentation and Evaluation Milestone  
**Authoritative Scope Document:** [`docs/PROJECT_SCOPE.md`](PROJECT_SCOPE.md)  
**Master Roadmap Reference:** [`docs/ROADMAP.md`](ROADMAP.md)  
**Monorepo Verification Baseline:** 281 / 281 Automated Tests Passing (100%) • 4/4 Workspaces Clean Build  

---

## 1. Executive Milestone Alignment

The PhishNetra academic major project spans approximately ten months divided into two distinct academic semesters.

To ensure academic rigor, technical defensibility, and honest evaluation before the evaluation panel, the project codebase and documentation are strictly partitioned into three verifiable categories:

1. **Implemented in Semester 1 (Working Prototype & Proof of Concept):**  
   Core engineering deliverables that demonstrably exist, compile, run, and pass automated unit/integration tests in the current repository.
2. **Prototype / Partially Implemented:**  
   Components for which functional implementations exist, but where comprehensive empirical evaluation, cross-browser compatibility, broad file format support, or real-time lifecycle hardening remains in progress.
3. **Planned for Semester 2 (Completion & Empirical Evaluation Roadmap):**  
   Substantial, research-driven engineering milestones that advance the project toward its full academic thesis without introducing artificial feature bloat.

---

## 2. Definitive Capability Audit & Milestone Mapping

| Capability | Actual Status | Semester 1 Treatment | Semester 2 Work | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **URL Threat Analysis & Canonicalization** | **Fully Implemented & Verified** | **Retain as Primary P0 Core**<br/>Deterministic canonicalization, lexical feature extraction, structural delimiters, Shannon entropy. | **Empirical Validation**<br/>Feature weight sensitivity analysis, adversarial evasion testing (homoglyph permutations, subdomains). | • `apps/api/src/services/analysis/canonicalization.ts`<br/>• `apps/api/src/services/analysis/urlLayer.ts`<br/>• `tests/canonicalization.test.ts` (5 tests passing)<br/>• `tests/layers.test.ts` (Layer 1: 3 tests passing) |
| **Baseline Machine Learning Model** | **Operational Baseline Prototype** | **Retain Baseline Random Forest**<br/>Fast inference (<5ms) on 18 deterministic lexical features with SHAP explainability. | **Comprehensive Benchmark Evaluation**<br/>Train/test evaluation on curated standard datasets (PhishTank, Alexa benign), F1/AUC metrics, latency profiling. | • `services/ml/app/model/pipeline.py`<br/>• `services/ml/app/features/extractor.py`<br/>• `services/ml/app/model/registry.py`<br/>• 58 Pytest tests passing (`services/ml/tests`) |
| **Multi-Layer Zero-Trust Risk Engine** | **Operational Multi-Layer Pipeline** | **Retain Working Signals & Invariants**<br/>Parallel RDAP domain age, DNS resolution, TLS certificate inspection, blacklist lookups, NaN-safe scoring. | **Dynamic Calibration & Live Feeds**<br/>Empirical calibration of layer weights, live provider rate-limit handling, degraded-state telemetry. | • `apps/api/src/services/risk/RiskEngineService.ts`<br/>• `apps/api/src/services/analysis/domainLayer.ts`<br/>• `apps/api/src/services/analysis/dnsLayer.ts`<br/>• `tests/multilayer_risk.test.ts` (3 tests passing) |
| **Webpage & Brand Content Analysis** | **Sandboxed Prototype Subset** | **Retain Sandboxed Prototype**<br/>SSRF-protected fetching, form action check, cross-origin password target, top-15 brand domain mismatch. | **Advanced Visual & DOM Evaluation**<br/>Computer vision logo similarity (YOLO/CLIP), anti-cloaking detection, rendering timeout optimization. | • `services/ml/app/analyzer/dom_parser.py`<br/>• `services/ml/app/analyzer/page_fetcher.py`<br/>• `tests/page_analysis.test.ts` (3 tests passing)<br/>• `services/ml/tests/test_ssrf.py` (26 tests passing) |
| **Email Attachment Link Analysis** | **Verified Vertical Slice** | **Retain Safe Tested Slice**<br/>Safe pure-JS extraction from PDF, HTML, DOCX, TXT/EML. Deduplication, 10MB limit, multi-layer evaluation. | **Extended Format Coverage & Hardening**<br/>Support for OpenXML XLSX/PPTX, encrypted PDF handling, nested archive inspection, obfuscated link refanging. | • `apps/api/src/services/ingestion/AttachmentAnalysisService.ts`<br/>• `apps/api/src/controllers/ingest.controller.ts`<br/>• `apps/web/src/pages/AttachmentScannerPage.tsx`<br/>• `tests/attachment_analysis.test.ts` (10 tests passing) |
| **Chrome Browser Extension (MV3)** | **Working Proof of Concept** | **Showcase Working Prototype**<br/>Background tab monitoring (`tabs.onUpdated`), sub-5ms local heuristics, popup console, DOM interstitial barrier overlay. | **Lifecycle Interception Hardening**<br/>`declarativeNetRequest` dynamic rule injection to guarantee zero first-byte leakage, cross-browser MV3 compatibility. | • `apps/extension/src/background/serviceWorker.ts`<br/>• `apps/extension/src/content/interstitial.ts`<br/>• `apps/extension/tests/heuristics.test.ts` (7 tests)<br/>• `apps/extension/tests/storage.test.ts` (5 tests) |
| **Dashboard & Telemetry History** | **Fully Functional Minimal UI** | **Retain Focused Academic Interface**<br/>Dashboard overview, Live URL Scanner, Attachment Scanner, Telemetry History with search/export, Extension guide. | **Evaluation Dashboards & User Studies**<br/>Comparative metric visualizations, usability study telemetry on interstitial warning compliance. | • `apps/web/src/pages/DashboardPage.tsx`<br/>• `apps/web/src/pages/AnalyzePage.tsx`<br/>• `apps/web/src/pages/AnalysisHistoryPage.tsx`<br/>• `apps/web/src/components/Navbar.tsx` |
| **Batch Processing & Supporting Tools** | **Verified Supporting Utilities** | **Retain Essential Utilities Only**<br/>BullMQ batch URL processing (`/batch`) and domain typosquatting matrix (`/domains`) for bulk evaluation. | **High-Throughput Optimization**<br/>Stream processing for high-volume corporate log analysis, worker concurrency auto-scaling. | • `apps/api/src/services/queue/workerQueue.ts`<br/>• `apps/api/src/services/analysis/typosquatting.ts`<br/>• `tests/queue_batch.test.ts` (4 tests passing)<br/>• `tests/typosquatting.test.ts` (6 tests passing) |
| **Enterprise SOC & Governance Modules** | **Implemented in Exploratory Sprints** | **Explicitly Defer from Active UI**<br/>Preserve in backend and test suite for backward compatibility, but hide from active navigation to protect thesis focus. | **Post-Academic / Enterprise Scope**<br/>SOAR playbooks, SIEM forwarders, BGP radar, FIDO2 admin, and TAXII threat exchange remain outside core research thesis. | • Backend routes preserved under `/api/*`<br/>• Tests passing in `tests/soar_playbooks.test.ts`, `tests/cti_bgp_fido2.test.ts`<br/>• Removed from primary UI navigation |

---

## 3. Semester 1 Demonstration Sequence

The Semester 1 evaluation will be conducted using the following reproducible demonstration:

1. **System Presentation & Research Context (1 min):**  
   Explain why single-signal URL blacklists fail against modern fast-flux, zero-day phishing, and how PhishNetra's multi-layer Zero-Trust architecture addresses the problem.
2. **Live Multi-Layer URL Threat Scan (2 min):**  
   Submit a controlled suspicious fixture (`http://secure-login-update-paypal-verification.com/account`). Demonstrate canonicalization, domain age calculation (<48h), DNS resolution, TLS inspection, Random Forest prediction, and SHAP explainable evidence.
3. **Email Attachment Link Extraction Vertical Slice (2 min):**  
   Upload a controlled test PDF attachment (`Payroll_Update_Notice.pdf`) or select a pre-loaded sample. Show safe non-executable hyperlink extraction, deduplication, and automated submission through the multi-layer pipeline. Demonstrate clear verdict communication (`THREATS_DETECTED` vs `NO_SUSPICIOUS_URLS_FOUND` vs `UNABLE_TO_ANALYZE`).
4. **Browser Extension Prototype & Interstitial Barrier (1.5 min):**  
   Demonstrate the Chrome Manifest V3 extension: show rapid local heuristic filtering (<5ms), API backend query, toolbar badge updates (`OK` / `BLOCK`), and trigger the DOM interstitial barrier overlay (`interstitial.ts`) with user choice options (Return to Safety / Inspect Details / Conscious Bypass).
5. **Semester 2 Roadmap & Questions (0.5 min):**  
   Outline the Semester 2 milestones: standardized dataset evaluation (precision, recall, F1, ROC-AUC), latency profiling, declarative navigation lifecycle hardening, and cross-browser support.

---

## 4. Test Suite & Build Verification Evidence

```
================================================================================
                    PHISHNETRA VERIFICATION BASELINE AUDIT
================================================================================
Workspace / Target          Test Runner    Suites    Passed    Failed   Pass Rate
--------------------------------------------------------------------------------
@phishnetra/api (Express)   Jest           29        202       0        100.0%
@phishnetra/extension (MV3) Jest            2         12       0        100.0%
services/ml (FastAPI)       Pytest          9         67       0        100.0%
--------------------------------------------------------------------------------
MONOREPO TOTAL                             40        281       0        100.0%
================================================================================
Production Builds:
  - @phishnetra/shared:    CLEAN (tsc)
  - @phishnetra/api:       CLEAN (tsc)
  - @phishnetra/web:       CLEAN (tsc && vite build - 1610 modules transformed)
  - @phishnetra/extension: CLEAN (tsc && vite build - 1519 modules transformed)
================================================================================
```
