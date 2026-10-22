# PhishNetra — Official Project Scope & Milestone Specification

**Official Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Classification:** Academic Major Project (Two-Semester / 10-Month Timeline)  
**Current Milestone:** Semester 1 Presentation & Evaluation (Months 1–5)  
**Authoritative Milestone Audit:** [`docs/SEMESTER_MILESTONE_AUDIT.md`](SEMESTER_MILESTONE_AUDIT.md)  
**Two-Semester Roadmap:** [`docs/ROADMAP.md`](ROADMAP.md)  

---

## 1. Problem Statement & Research Questions

Phishing attacks remain the predominant initial access vector for credential theft and malware delivery. Traditional defenses rely heavily on static, reactive URL blacklists (e.g., Google Safe Browsing, DNS blocklists) that suffer from significant dwell times (hours to days) before newly registered adversary infrastructure is indexed. Modern phishing campaigns utilize fast-flux DNS, freshly registered lookalike domains, subtle Unicode homoglyphs, and evasive delivery mechanisms—notably **embedded URLs inside email attachments (PDF, HTML, DOCX, TXT)**—that completely bypass static perimeter filters.

Furthermore, web users lack explainable, real-time feedback during navigation, leading to accidental credential entry on convincing imitation portals.

PhishNetra addresses this challenge through an integrated, defense-in-depth framework answering six core research and engineering questions:

1. **Is the URL suspicious or potentially malicious?** (Lexical heuristics, domain age, DNS anomalies, reputation feeds, ML classification).
2. **What evidence supports the classification?** (Explainable layer attribution, confidence ratings, and feature contributions).
3. **Does the webpage exhibit phishing indicators not visible from the URL alone?** (Isolated DOM form inspection, cross-origin credential harvesting, brand domain mismatch).
4. **Does an email attachment contain URLs that lead to phishing destinations?** (Safe attachment parsing, embedded hyperlink extraction, and multi-layer link evaluation).
5. **Can the browser extension communicate the risk before or during navigation?** (Manifest V3 extension with active tab monitoring, instant local pre-filtering, and zero-silent-redirect warning interstitials).
6. **What should the user do based on the evidence?** (Actionable mitigation advice: safe navigation return, details inspection, or conscious bypass).

---

## 2. Semester 1 Milestone: Working Prototype & Proof of Concept

The Semester 1 deliverable demonstrates the fundamental research thesis through a functional, explainable multi-layer detection pipeline and verified endpoint/attachment prototypes:

### A. Core Multi-Layer URL Threat Pipeline (`apps/api`)
- **Layer 0 (Canonicalization):** RFC 3986 normalization, Punycode/IDN homoglyph translation, default port stripping, duplicate slash collapsing.
- **Layer 1 (Lexical Engine):** 16 structural features including Shannon entropy, token depth, IP literal detection, and credential delimiters (`@`).
- **Layer 2 (Domain Intelligence):** RDAP registration age verification (`<30d`, `30-90d`, `90-365d`, `>365d`) with zero-trust flags for fresh domains (<48h).
- **Layer 3 (Passive DNS & IP):** Bogon IP detection, RFC 1918 private range SSRF immunity, fast-flux TTL inspection.
- **Layer 4 (TLS Handshake):** Certificate hostname verification, self-signed detection, lifetime inspection.
- **Layer 5 (Reputation Intel):** URLhaus, local blacklists, and simulated feed provider abstraction.
- **Layer 6 (Baseline Machine Learning):** Scikit-learn Random Forest classifier (`services/ml`) operating on 18 deterministic lexical features with Tree-SHAP explainability.
- **Decision Engine:** Zero-Trust composite scoring (0–100), NaN-safe normalization, deterministic layer weighting, and explainable evidence synthesis.

### B. Email Attachment Link Analysis Vertical Slice (`apps/api` & `apps/web`)
- **Safe Parsing Engine:** Pure-JavaScript extraction of hyperlinks from supported file formats:
  - **PDF:** URI action dictionaries (`/Type /Action /S /URI`) and text annotations.
  - **HTML:** Anchor tags (`<a href>`), form targets (`<form action>`), and `<meta http-equiv="refresh">`.
  - **DOCX:** OpenXML relationship XML targets (`Target="http..."`).
  - **TXT / EML:** Plain text and defanged URLs (`hxxp://`, `[.]`).
- **Safety Boundary:** Declarative in-memory parsing; **zero execution of active code, macros, or native binaries**.
- **Integrated Analysis:** Extracted links are deduplicated and automatically evaluated through the multi-layer pipeline.
- **Clear Distinction:** Unambiguous verdict reporting (`THREATS_DETECTED` vs `NO_SUSPICIOUS_URLS_FOUND` vs `UNABLE_TO_ANALYZE`).

### C. Browser Extension Proof of Concept (`apps/extension`)
- **Manifest V3 Architecture:** Chrome extension with background service worker and content script overlay.
- **Local Heuristics Pre-Filter:** Sub-5ms client-side entropy and homoglyph evaluation.
- **Backend API Integration:** Asynchronous threat lookup via `POST /api/analyze`.
- **Badge Signaling & DOM Barrier:** Dynamic toolbar badge (`OK`, `WARN`, `BLOCK`) and high-risk DOM interstitial barrier (`interstitial.ts`) providing user choices.

### D. Academic Research Dashboard (`apps/web`)
- **Overview:** Real-time threat telemetry and scan metrics.
- **Live URL Scanner (`/analyze`):** Interactive URL submission with 8-layer visual breakdown and SHAP explainability.
- **Attachment Scanner (`/attachments`):** Drag-and-drop file upload, sample presets, and extracted URL threat breakdown.
- **Investigation History (`/history`):** Searchable, filterable audit log with JSON export.
- **Extension Guide (`/extension`):** Architecture walkthrough and interactive interstitial barrier preview.

---

## 3. Prototype / Partially Implemented Capabilities

The following features have functional initial implementations in the codebase, but their comprehensive evaluation, coverage, or real-time guarantees remain ongoing work:

1. **Webpage DOM & Brand Analysis (`services/ml`):**
   - *Current Status:* Working prototype utilizing sandboxed fetching with SSRF protection, inspecting forms and checking against a 15-brand catalog for `BRAND_DOMAIN_MISMATCH`.
   - *Limitation:* Headless Chromium rendering is resource-intensive and subject to anti-bot cloaking. Marked as an optional toggle (`analyzePage: boolean`).
2. **Browser Extension Real-Time Navigation Interception:**
   - *Current Status:* Working proof-of-concept using `tabs.onUpdated` and DOM injection.
   - *Limitation:* Does not yet enforce `declarativeNetRequest` rules to guarantee zero first-byte leakage before backend API response completes.
3. **Attachment Format Breadth:**
   - *Current Status:* Working vertical slice for PDF, HTML, DOCX, TXT, and EML.
   - *Limitation:* Binary legacy formats (`.doc`), spreadsheets (`.xlsx`), encrypted archives, and macro sandboxing are not evaluated.

---

## 4. Semester 2 Objectives & Research Roadmap

Semester 2 advances the research thesis toward a complete, academically evaluated framework:

### A. Rigorous Empirical Evaluation & Benchmarking
- **Standard Benchmark Datasets:** Curate and evaluate against standard academic datasets (e.g., PhishTank, Alexa Top 1M benign set, Mendeley Phishing URL Dataset) with documented splits.
- **Performance Metrics:** Measure classification accuracy, precision, recall, F1 score, and ROC-AUC.
- **Latency Profiling:** Measure end-to-end latency distributions across individual layers and evaluate throughput under concurrent load.
- **Comparative Baseline Analysis:** Benchmark the multi-layer approach against single-signal baselines (Google Safe Browsing alone, Random Forest alone).

### B. Complete Browser-Level Protection
- **Declarative Navigation Interception:** Implement `chrome.declarativeNetRequest` dynamic rulesets to eliminate first-byte leakage before analysis completes.
- **Cross-Browser Compatibility:** Expand extension support to Firefox (MV2/MV3) and Microsoft Edge.
- **Privacy-Preserving Local Cache:** Implement client-side Bloom filters for known malicious hostnames to minimize external API roundtrips.

### C. Extended Attachment & Content Analysis
- **Expanded File Formats:** Add safe link extraction for OpenXML XLSX/PPTX, RTF, and nested archive structures.
- **Obfuscation & Redirect Tracking:** Resolve shortened and multi-hop redirect chains within attachment URLs.
- **Computer Vision Brand Identification:** Prototype logo similarity analysis (YOLO/CLIP) to complement HTML DOM attribute matching.

### D. System Hardening & Thesis Defense
- **Dynamic Risk Calibration:** Calibrate layer weights empirically using validation loss.
- **Academic Thesis & Defense:** Compile comprehensive methodology, threats to validity, empirical results, and final defense documentation.

---

## 5. Explicitly Deferred Enterprise Features

During exploratory iterations, several enterprise SOC modules were developed that exceed the core academic project scope. To ensure a clear, defensible presentation, these modules are **removed from active navigation** and preserved strictly in the backend for backward compatibility:

- Autonomous SOAR Playbook Containment (`/playbooks`)
- Enterprise SOC Incident Case Management (`/cases`)
- Remote Browser Isolation (RBI) Container Stubs (`/rbi-sandbox`)
- Phishing Tarpit Credential Flooder (`/tarpit`)
- STIX/TAXII 2.1 Threat Exchange (`/cti-exchange`)
- BGP Route Integrity Radar (`/bgp-integrity`)
- FIDO2 / WebAuthn Policy Administration (`/fido2-guard`)
- External Attack Surface Management (`/attack-surface`)
- Telecom Vishing Threat Fusion (`/telecom-threat`)
- Board-Level Executive Briefings (`/executive-briefing`)

---

## 6. Known Limitations (Semester 1 Baseline)

1. **Passive Attachment Parsing:** Attachment link analysis extracts embedded hyperlinks; it does not perform binary malware analysis or OS-level sandbox detonation.
2. **External Feed Rate Limits:** Live threat intelligence providers (URLhaus, VirusTotal) are subject to external API availability and rate limits. The system fails safe by marking providers as `UNAVAILABLE` rather than defaulting to `SAFE`.
3. **Headless Execution Overhead:** Remote DOM fetching adds 1.5–3.5s latency per page; therefore, DOM analysis is an optional secondary step rather than a prerequisite for URL evaluation.
