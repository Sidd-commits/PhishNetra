# PhishNetra — Master Scope Audit & Feature Classification

**Date:** October 2026  
**Auditor:** Senior Software Architect & Refactoring Specialist  
**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Context:** Academic Major Project (10-Month Timeline) — Alignment for Final Project Defense

---

## 1. Executive Summary

PhishNetra was designed to solve a clear, practical cybersecurity research problem:
> **Build a multilayered, AI-assisted phishing detection framework that operates through a browser extension, evaluates suspicious URLs, examines webpage indicators, identifies malicious URLs embedded in supported email attachments, and provides timely, explainable browser-level warnings or mitigation.**

Over the course of rapid development, the codebase expanded into 20 milestones containing numerous enterprise-scale features (such as BGP route hijacking radar, decentralized STIX/TAXII threat exchanges, FIDO2 admin consoles, SOAR playbook automation, active honeypots, legal takedown dispatchers, and telecom STIR/SHAKEN fusion). While technically ambitious, these enterprise SOC modules are out of scope for the core research thesis, dilute the demonstration, and shift focus away from the primary browser extension and email attachment phishing detection problem.

This audit classifies all existing modules into four authoritative categories:
- **`CORE`**: Retain, harden, and treat as the primary demonstration deliverables.
- **`SUPPORTING`**: Retain as necessary dependencies for the core capabilities.
- **`DEFERRED`**: Remove from the active product navigation and interface; document as potential future enterprise research extensions.
- **`REMOVE`**: Safely retire unneeded or misleading elements.

---

## 2. Feature Inventory & Classification Matrix

| Feature / Module | Location (Route / Component) | Backend Endpoints & Services | Scope Alignment | Category | Action & Justification |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Manifest V3 Browser Extension** | `apps/extension` (Popup, Content Script, Interstitial Shield, Options) | Integrates with `/api/analyze` | Direct P0 Core | **CORE** | **Retain & Prioritize:** Primary user-facing product deliverable. Intercepts navigation, evaluates links, and displays explainable warnings. |
| **Multi-Layer URL Detection Pipeline** | `/analyze`<br>`AnalysisPage.tsx`<br>`AnalysisDetailPage.tsx` | `POST /api/analyze`<br>`AnalysisService.ts`<br>`RiskEngine.ts` | Direct P0 Core | **CORE** | **Retain & Prioritize:** Core zero-trust URL inspection synthesizing lexical, RDAP, DNS, TLS, and reputation signals. |
| **Baseline ML Inference Engine** | ML Microservice (`services/ml`) | `POST /predict`<br>`baseline.py`<br>`url_features.py` | Direct P0 Core | **CORE** | **Retain & Prioritize:** Fast (<5ms) Random Forest model extracting 18 deterministic URL features with local SHAP attribution. |
| **Secure Webpage & DOM Content Analyzer** | Embedded in `/analyze/:id`<br>`PageAnalysisView.tsx` | `page_analyzer.py`<br>`ssrf.py`<br>`brand_analyzer.py` | Direct P0 Core | **CORE** | **Retain & Prioritize:** Inspects HTML forms, external scripts, brand mismatch, and urgency keywords inside isolated sandbox with SSRF immunity. |
| **Email Attachment URL Analysis** | `/attachments` (Refactored from `/email-scanner`)<br>`AttachmentScannerPage.tsx` | `POST /api/ingest/attachment`<br>`AttachmentAnalysisService.ts`<br>`EmailIngestionService.ts` | Direct P0 Core | **CORE** | **Prioritize & Upgrade:** Extracts embedded URLs from supported attachments (PDF, HTML, TXT, DOCX/EML), normalizes links, and runs them through the core analysis pipeline. |
| **Dashboard Overview** | `/dashboard`<br>`DashboardPage.tsx` | `GET /api/analyze/history`<br>`GET /api/health` | P1 Supporting | **SUPPORTING** | **Retain & Streamline:** Simplify to focus exclusively on URL scans, attachment reports, and browser extension status. Remove enterprise SOC clutter. |
| **Analysis History** | `/history` & `/analyze/:id` | `GET /api/analyze/history`<br>`GET /api/analyze/:id` | P1 Supporting | **SUPPORTING** | **Retain:** Essential for reviewing past investigations, evidence items, and layer breakdowns. |
| **Batch URL Queue Ingestion** | `/batch`<br>`BatchAnalysisPage.tsx` | `/api/batch`<br>`BatchService.ts`<br>`AsyncAnalysisQueue.ts` | P1 Supporting | **SUPPORTING** | **Retain under Tools:** High-capacity bulk URL scanner for processing lists of URLs asynchronously. |
| **Domain Dossier & Typosquatting Hub** | `/domains`<br>`DomainHubPage.tsx` | `/api/domains/:domain`<br>`DomainService.ts`<br>`typosquatting.ts` | P1 Supporting | **SUPPORTING** | **Retain under Tools:** Crucial for inspecting domain age, nameservers, and Unicode lookalike homoglyphs. |
| **System Settings & Health Telemetry** | `/settings`<br>`SettingsPage.tsx` | `/api/settings/config`<br>`/api/health`<br>`SettingsService.ts` | P1 Supporting | **SUPPORTING** | **Retain:** Provides essential configuration of detection thresholds and service health status. |
| **Decentralized CTI TAXII 2.1 Exchange** | `/cti-exchange`<br>`CTIExchangePage.tsx` | `/api/cti-exchange`<br>`TAXIIClientService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Generic enterprise threat exchange unrelated to browser extension phishing warnings. |
| **BGP Route Hijacking & DNS Radar** | `/bgp-integrity`<br>`BGPIntegrityPage.tsx` | `/api/bgp-integrity`<br>`BGPRouteIntegrityService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Infrastructure routing analysis outside the URL/attachment phishing detection scope. |
| **FIDO2 / WebAuthn Admin Console** | `/fido2-guard`<br>`FIDO2GuardPage.tsx` | `/api/fido2-guard`<br>`FIDO2CredentialGuardService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Passkey admin simulator; browser extension directly protects users from credential harvesting without requiring this admin console. |
| **Threat Actor Attribution Matrix** | `/threat-attribution`<br>`ThreatAttributionPage.tsx` | `/api/attribution`<br>`ThreatActorAttributionService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Nation-state APT attribution is unrelated to real-time browser warning mitigation. |
| **Quantitative Cyber Risk (FAIR Model)** | Embedded in `/threat-attribution` | `/api/risk-quantification`<br>`CyberRiskQuantificationService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Actuarial financial risk modeling is not part of an AI detection system thesis. |
| **External Attack Surface Management** | `/attack-surface`<br>`AttackSurfacePage.tsx` | `/api/attack-surface`<br>`AttackSurfaceService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Perimeter port/asset discovery is outside the URL/browser warning thesis. |
| **Telecom Multi-Vector Threat Fusion** | `/telecom-threat`<br>`TelecomThreatPage.tsx` | `/api/telecom-threat`<br>`TelecomThreatFusionService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Carrier STIR/SHAKEN and acoustic call analysis are outside browser extension scope. |
| **MITRE D3FEND Countermeasure Matrix** | `/d3fend`<br>`D3FENDPage.tsx` | `/api/d3fend`<br>`D3FENDMappingService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Enterprise defense ontology browser is not a core detection feature. |
| **SOAR Playbooks & Containment** | `/playbooks`<br>`PlaybookStudioPage.tsx` | `/api/playbooks`<br>`PlaybookOrchestrationEngine.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Automated firewall/DNS sinkhole orchestration is out of academic scope. |
| **SOC Incident Case Management** | `/cases`<br>`CaseManagementPage.tsx` | `/api/cases`<br>`CaseManagementService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Generic ticketing/ITSM workbench does not contribute to phishing detection. |
| **Legal Abuse Takedown Center (RFC 2142)** | `/takedowns`<br>`TakedownCenterPage.tsx` | `/api/takedowns`<br>`TakedownService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Registrar abuse emails are out of browser mitigation scope. |
| **SIEM Forwarding & Webhook Management** | `/siem`, `/integrations`<br>`SIEMIntegrationPage.tsx` | `/api/siem`, `/api/notifications`<br>`SIEMExportEngine.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Enterprise log exporter (CEF/LEEF) is an enterprise ops tool, not core detection. |
| **Multi-Tenant Team Workspaces (RBAC)** | `/organization`<br>`OrganizationPage.tsx` | `/api/organizations`<br>`OrganizationService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** SaaS subscription and workspace quotas are irrelevant to the core thesis. |
| **Phishing Tarpit & Credential Poisoner** | `/tarpit`<br>`TarpitDefensePage.tsx` | `/api/tarpit`<br>`PhishingTarpitService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Flooding adversary servers with synthetic credentials is active offense/tarpitting. |
| **Canary Deception & Honeypots** | `/deception`<br>`CanaryDeceptionPage.tsx` | `/api/deception`<br>`CanaryDeceptionService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Decoy honeypots are out of scope for a browser extension detection tool. |
| **Remote Browser Isolation (RBI)** | `/rbi-sandbox`<br>`RBISandboxPage.tsx` | `/api/rbi`<br>`RemoteBrowserIsolationService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Ephemeral Docker container streaming is heavy enterprise infrastructure. The core sandbox analysis is already executed safely via the ML service. |
| **Threat Simulation & Attack Replay** | `/simulation`<br>`SimulationPage.tsx` | `/api/simulation`<br>`AttackSimulationService.ts` | Evaluation / Benchmark | **DEFERRED (from UI)** | **Remove from Active Nav:** Retain as an automated backend regression and benchmark test suite; hide from consumer UI. |
| **Threat Hunting Lab** | `/hunting`<br>`ThreatHuntingPage.tsx` | `/api/hunting`<br>`ThreatHuntingService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Generic regex/JA3 query engine for SOC analysts is out of scope. |
| **Digital Forensics & HAR Packet Inspection** | `/digital-forensics`<br>`DigitalForensicsPage.tsx` | `/api/digital-forensics`<br>`DigitalForensicsService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Courtroom chain-of-custody HAR inspection is out of real-time detection scope. |
| **Continuous Session Trust Verification** | `/session-anomaly`<br>`SessionAnomalyPage.tsx` | `/api/session-anomaly`<br>`ContinuousSessionService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Post-auth token hijacking detection is out of scope for URL/attachment phishing. |
| **Client-Side Anti-Tamper SDK** | `/client-defense`<br>`ClientDefensePage.tsx` | `/api/client-defense`<br>`ClientTamperDefenseService.ts` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** Webmaster script injection is out of scope for user-side browser extension defense. |
| **Threat Graph & Campaign Explorer** | `/graph`, `/campaigns`<br>`ThreatGraphPage.tsx` | `/api/graph`, `/api/campaigns`<br>`ThreatGraphEngine.ts` | Complex Supporting | **DEFERRED (from UI)** | **Remove from Primary Nav:** Keep backend graph co-location analysis intact; hide dedicated graph workbench. |
| **Executive Briefing Dossier** | `/executive-briefing`<br>`ExecutiveBriefingPage.tsx` | `/api/reports/executive` | Enterprise Out-of-Scope | **DEFERRED** | **Remove from Active Nav:** C-suite board presentations are out of academic project scope. |
| **GenAI Prompt Defense & Quishing** | `/genai-defense`, `/quishing` | `/api/genai-defense`, `/api/quishing` | Experimental / Secondary | **DEFERRED** | **Consolidate or Defer:** Move QR link scanning into the unified attachment/link scanner; remove dedicated prompt-defense UI. |

---

## 3. Approved Streamlined Navigation Structure

The complex 3-group mega-dropdown structure (`Detection`, `Threat Intel`, `SOC Ops`) with 35+ items is completely replaced by a clean, coherent, academic-focused navigation bar:

1. **Dashboard** (`/dashboard`): Real-time metrics on analyzed URLs, high-risk detections, attachment evaluations, and extension connectivity.
2. **URL Threat Scanner** (`/analyze`): Multi-layer URL inspection, risk gauge, layer breakdowns, and isolated webpage indicator findings.
3. **Attachment Link Scanner** (`/attachments`): Dedicated drag-and-drop file analyzer extracting and scanning embedded URLs from PDF, HTML, TXT, and DOCX/EML attachments.
4. **Domain Intelligence** (`/domains`): RDAP domain age verification and typosquatting/homoglyph detection.
5. **Batch Scanner** (`/batch`): Bulk asynchronous URL evaluation.
6. **Analysis History** (`/history`): Review of past URL and attachment scan outcomes with complete evidence trails.
7. **Extension Guide** (`/extension`): Overview of the Manifest V3 browser extension, active protections, and local installation instructions.
8. **Settings** (`/settings`): Core detection thresholds, API connectivity, and service health checks.

---

## 4. Key Actions & Refactoring Plan

1. **Implement Dedicated Attachment URL Extraction Service (`AttachmentAnalysisService.ts`)**:
   - Safe parsing of **PDF** (URI dictionary links + plain text URLs).
   - Safe parsing of **HTML** (`<a href>`, `<form action>`, `<meta refresh>`, and text URLs).
   - Safe parsing of **TXT** (regular expression text extraction with defanging support `hxxp://`, `[.]`).
   - Safe parsing of **DOCX / EML** (relationship hyperlinks + body URLs).
   - Strict size caps (max 10MB) and parsing timeouts.
   - Batch analysis of all extracted URLs through the shared `AnalysisService` pipeline.
   - Clear distinction between `NO_SUSPICIOUS_URLS_FOUND` vs `UNABLE_TO_ANALYZE`.
2. **Streamline Navigation & Remove Clutter**:
   - Refactor `Navbar.tsx` and mobile navigation.
   - Remove out-of-scope dropdowns (`Threat Intel`, `SOC Ops`).
   - Add direct links to the primary deliverables: `URL Scanner`, `Attachment Scanner`, `Extension Guide`.
3. **Refactor Dashboard (`DashboardPage.tsx`)**:
   - Display genuine data: Total URLs analyzed, high-risk threats prevented, attachments inspected, links extracted, and extension status.
   - Eliminate placeholder metrics for unneeded enterprise SOC items.
4. **Preserve Existing Backend & Security Foundations**:
   - Keep all existing database tables, models, and shared utilities intact (no destructive drops).
   - Maintain SSRF protections, canonicalization, and zero-trust scoring invariants.
5. **Update Documentation**:
   - Create `docs/PROJECT_SCOPE.md` detailing the research problem, P0/P1 boundaries, and in-scope questions.
   - Update `docs/ROADMAP.md` to reflect the 10-month master scope with verified status.
   - Update `docs/ARCHITECTURE.md` focusing on the browser extension, URL engine, and attachment pipeline.
   - Update `docs/API.md` highlighting the core verified endpoints.
