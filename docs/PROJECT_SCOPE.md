# PhishNetra — Official Project Scope & Specifications

**Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Classification:** Academic Major Project (10-Month Timeline)  
**Status:** Scope-Aligned & Production-Ready for Project Presentation

---

## 1. Problem Statement

Phishing attacks remain the predominant initial access vector for credential theft and malware delivery. Traditional defenses rely heavily on static, reactive URL blacklists (e.g., Google Safe Browsing, DNS blocklists) that suffer from significant dwell times (hours to days) before newly registered adversary infrastructure is indexed. Modern phishing attacks utilize fast-flux DNS, freshly registered lookalike domains, subtle Unicode homoglyphs, and evasive delivery mechanisms—notably **embedded URLs inside email attachments (PDF, HTML, DOCX, TXT)**—that completely bypass static gateway filters.

Furthermore, average web users lack explainable, real-time feedback during navigation, leading to accidental credential entry on convincing imitation portals.

---

## 2. Research & Engineering Objectives

PhishNetra addresses this challenge through an integrated, defense-in-depth framework answering six core questions:

1. **Is the URL suspicious or potentially malicious?** (Lexical heuristics, domain age, DNS anomalies, reputation feeds, ML classification).
2. **What evidence supports the classification?** (Explainable layer attribution, confidence ratings, and feature contributions).
3. **Does the webpage exhibit phishing indicators not visible from the URL alone?** (Isolated DOM form inspection, cross-origin credential harvesting, brand domain mismatch).
4. **Does an email attachment contain URLs that lead to phishing destinations?** (Safe attachment parsing, embedded hyperlink extraction, and multi-layer link evaluation).
5. **Can the browser extension communicate the risk before or during navigation?** (Manifest V3 extension with active tab monitoring, instant local pre-filtering, and zero-silent-redirect warning interstitials).
6. **What should the user do based on the evidence?** (Actionable mitigation advice: safe navigation return, DNS sinkholing, or explicit analyst review).

---

## 3. In-Scope Functionality (P0 & P1)

### Priority 0 — Core Capabilities
- **Manifest V3 Browser Extension (`apps/extension`):**
  - Instant client-side lexical pre-filter (<5ms).
  - Real-time tab interception and badge risk signaling.
  - Zero-silent-redirect threat interstitial warning screen.
  - Interactive popup inspection console and domain whitelisting.
- **Multi-Layer Zero-Trust URL Analysis Pipeline (`apps/api`):**
  - Layer 0: URL Canonicalization Engine (Punycode IDN, port normalization).
  - Layer 1: URL Structural Heuristics & Shannon Entropy.
  - Layer 2: Domain Intelligence & RDAP Age Verification (`<30d`, `30-90d`, `90-365d`, `>365d`).
  - Layer 3: Passive DNS & RFC 1918 Private IP SSRF Immunity.
  - Layer 4: TLS Socket Handshake & Certificate Hostname Validation.
  - Layer 5: Threat Reputation Provider Abstraction (URLhaus, PhishTank, VirusTotal).
  - Layer 6: Baseline ML Random Forest Inference & Tree-SHAP Explainability.
- **Secure Webpage & DOM Content Analysis (`services/ml`):**
  - Ephemeral isolated browser acquisition with strict execution timeouts (10s) and response caps (5MB).
  - Form action inspection (cross-origin credential posting, raw IP form destinations).
  - Brand impersonation catalog (15 top enterprise brands) and `BRAND_DOMAIN_MISMATCH` detection.
  - Social engineering urgency keyword scoring.
- **Email Attachment URL Analysis Pipeline (`apps/api`):**
  - Safe parsing of PDF files (URI dictionaries + plain text regex).
  - Safe parsing of HTML attachments (`<a href>`, `<form action>`, `<meta refresh>`).
  - Safe parsing of TXT / EML files (refanged URL extraction).
  - Safe parsing of DOCX documents (Relationship XML hyperlinks).
  - Full evaluation of all extracted URLs through the multi-layer pipeline.
  - Distinct reporting: `NO_SUSPICIOUS_URLS_FOUND` vs. `UNABLE_TO_ANALYZE`.

### Priority 1 — Necessary Supporting Infrastructure
- **Streamlined SOC Analyst Dashboard (`apps/web`):**
  - Overview cards: URLs scanned, high-risk detections, attachments analyzed, extension status.
  - Live Multi-Layer URL Scanner (`/analyze`).
  - Email Attachment Link Scanner (`/attachments`).
  - Domain Intelligence & Typosquatting Hub (`/domains`).
  - Asynchronous Batch URL Scanner (`/batch`).
  - Complete Investigation History (`/history` / `/analyze/:id`).
  - Browser Extension Guide & Health Status (`/extension`).
  - System Settings & Detection Calibration (`/settings`).
- **Resilience & Security Controls:**
  - Multi-tier in-memory LRU cache with Redis fallback.
  - Strict SSRF defense blocking RFC 1918, loopback, and cloud metadata (`169.254.169.254`).
  - Deterministic NaN-safe risk score normalization.

---

## 4. Explicitly Out of Scope

The following enterprise SOC and governance features were developed in exploratory iterations and are **deliberately deferred from the active user interface**:

- Enterprise SOC Case Management & Ticketing (`/cases`)
- Autonomous SOAR Playbook Containment Pipelines (`/playbooks`)
- Enterprise SIEM Exporter & Syslog Forwarding (`/siem`)
- Threat Actor Attribution & APT Matrices (`/threat-attribution`)
- BGP Route Hijacking & DNS Cache Poisoning Radar (`/bgp-integrity`)
- FIDO2 / WebAuthn Administration Consoles (`/fido2-guard`)
- Decentralized STIX/TAXII Threat Exchanges (`/cti-exchange`, `/api/taxii21`)
- Active Canary Honeypots & Deception (`/deception`)
- RFC 2142 Automated Registrar Abuse Takedowns (`/takedowns`)
- Phishing Tarpits & Synthetic Flooding (`/tarpit`)
- External Attack Surface Management (`/attack-surface`)
- Telecom STIR/SHAKEN Vishing Threat Fusion (`/telecom-threat`)
- Board-Level Executive Risk Reporting (`/executive-briefing`)
- FAIR Quantitative Actuarial Cyber Risk Modeling (`/risk-quantification`)
- Multi-Tenant Team Workspaces & SaaS Subscriptions (`/organization`)

*Note: The underlying backend implementations and database structures remain safely preserved in the repository; they are simply retired from active navigation to ensure a clean, defensible academic project scope.*

---

## 5. Expected Users & Operational Workflow

### Primary Persona: Web User / Knowledge Worker
1. User browses the web protected by the **PhishNetra Manifest V3 Browser Extension**.
2. When the user visits an unfamiliar or suspicious link, the extension queries the backend API.
3. If risk is elevated ($\ge 75$), an **immediate interstitial warning screen** blocks the page, neutralizing credential entry.
4. The user receives clear, explainable evidence (e.g., *"Brand mismatch: Page impersonates Microsoft 365 but points to a Russian IP on a 3-day-old domain"*).

### Secondary Persona: SOC Analyst / Security Researcher
1. Evaluates incoming suspicious URLs via the **Live URL Scanner** (`/analyze`).
2. Uploads suspicious email attachments (PDF, HTML, DOCX, TXT) to the **Attachment Link Scanner** (`/attachments`) to extract and evaluate all embedded hyperlinks.
3. Inspects domain registration age and homoglyph typosquats via the **Domain Hub** (`/domains`).
4. Reviews historical investigation records and exports forensic telemetry.
