# PhishNetra — System Architecture (Milestone 4)

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Current Milestone:** Milestone 4 (Async Distributed Architecture, Persistent Caching, High-Throughput Batch Engine & Domain Dossier Hub)

---

## 1. High-Level Architecture Diagram

```text
                        ┌────────────────────────────────────────────────────────┐
                        │               React SOC Web Dashboard                  │
                        │              (apps/web - Vite + Tailwind)              │
                        │  [/dashboard]  [/analyze]  [/batch]  [/domains]  [/reports] │
                        └───────────────────────────┬────────────────────────────┘
                                                    │ HTTP / REST + JWT
                                                    ▼
                        ┌────────────────────────────────────────────────────────┐
                        │                  Node.js Express API                   │
                        │                       (apps/api)                       │
                        └─────────────┬────────────────────────────┬─────────────┘
                                      │                            │
                 ┌────────────────────┴───────────┐                ▼
                 │ Async Batch Dispatcher & Queue │     ┌────────────────────────┐
                 │    (AsyncAnalysisQueue.ts)     │     │ Persistent Multi-Tier  │
                 │   [Concurrency: 5 Workers]     │     │      Cache Layer       │
                 └────────────────────┬───────────┘     │ (Redis / Memory LRU)   │
                                      │                 └──────────┬─────────────┘
                                      ▼                            │
                        ┌───────────────────────────┐              │
                        │       Risk Engine &       │◄─────────────┘
                        │ URL Canonicalization Core │
                        └─────────────┬─────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
      ┌───────────────┐       ┌───────────────┐       ┌───────────────┐
      │ Layer 1: URL  │       │Layer 2: Domain│       │ Layer 3: DNS  │
      │ Intelligence  │       │  Intel & RDAP │       │ & IP Intel    │
      │ (Lexical/Hex) │       │ (Age Category)│       │ (A/MX/SSRF)   │
      └───────┬───────┘       └───────┬───────┘       └───────┬───────┘
              │                       │                       │
              └───────────────┬───────┴────────┬──────────────┘
                              │                │
                              ▼                ▼
                      ┌───────────────┐ ┌───────────────┐
                      │ Layer 5: Feed │ │ Layer 6: URL  │
                      │  Reputation   │ │  ML Baseline  │
                      │(URLhaus/Virus)│ │ (FastAPI:8000)│
                      └───────┬───────┘ └───────┬───────┘
                              │                 │
                              └────────┬────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │   Secure Page Analysis Request    │
                     │ (Delegated to Isolated Python MS) │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
               ╔═══════════════════════════════════════════════╗
               ║       Isolated Analyzer Service (:8000)       ║
               ║  ┌─────────────────────────────────────────┐  ║
               ║  │ SSRF Defense & Pre-flight DNS Rebinding │  ║
               ║  └────────────────────┬────────────────────┘  ║
               ║                       ▼                       ║
               ║  ┌─────────────────────────────────────────┐  ║
               ║  │ Ephemeral Playwright / Chromium Context │  ║
               ║  │ (Route Interception, Resource Limits)   │  ║
               ║  └────────────────────┬────────────────────┘  ║
               ║                       ▼                       ║
               ║  ┌─────────────────────────────────────────┐  ║
               ║  │ Passive Extraction & Analysis Engines:  │  ║
               ║  │ • DOM Analyzer (Forms, Inputs, Scripts) │  ║
               ║  │ • Form Analyzer (Action, Cross-Origin)  │  ║
               ║  │ • JS Heuristics (Eval, Obfuscation)     │  ║
               ║  │ • Brand & Keyword Consistency Engine    │  ║
               ║  │ • Visual Analyzer (Viewport, Capture)   │  ║
               ║  └────────────────────┬────────────────────┘  ║
               ║                       ▼                       ║
               ║  ┌─────────────────────────────────────────┐  ║
               ║  │ 20-Dim Content Features & Content Model │  ║
               ║  └─────────────────────────────────────────┘  ║
               ╚═══════════════════════╤═══════════════════════╝
                                       │
                                       ▼
                          ┌─────────────────────────┐
                          │ Multi-Layer Risk Engine │
                          │  (8-Layer Calibrated)   │
                          └────────────┬────────────┘
                                       │
                       ┌───────────────┴───────────────┐
                       ▼                               ▼
          Structured Layer Evidence          SQLite / Prisma Database
          (Grouped & Tagged Signals)        (User, Analysis, BatchJob,
                                             BatchItem, CommunityReport)
```

---

## 2. Layer Interfaces & Weight Allocation

PhishNetra weights are engineered defaults configured centrally in `@phishnetra/shared`:

| Layer | Implementation Class | Responsibilities | Weight |
| :--- | :--- | :--- | :---: |
| **0. Canonicalization** | `canonicalizeUrl` | URL normalization, Punycode IDN conversion, port stripping, case normalization. | — |
| **1. URL Intelligence** | `URLLayer` | Structural metrics, Shannon entropy, obfuscated hex `%2F`, shortener detection. | **0.15** |
| **2. Domain Intelligence** | `DomainLayer` | Registrable domain, public suffix, RDAP gateway querying, domain age in days. | **0.10** |
| **3. DNS & IP Intelligence** | `DNSLayer` | Passive DNS lookup (A, AAAA, MX, NS, CNAME), RFC1918 private IP SSRF detection. | **0.08** |
| **4. TLS Intelligence** | `TLSLayer` | Non-intrusive TLS socket handshake, certificate validity, expiration, hostname matching. | **0.07** |
| **5. Reputation Intelligence** | `ReputationLayer` | Provider abstraction (`URLhausProvider`, `PhishTankProvider`, `VirusTotalProvider`). | **0.20** |
| **6. Machine Learning** | `MLClientService` | Random Forest classifier querying Python microservice on port 8000. | **0.15** |
| **7. Web Content & DOM** | `PageAnalyzerClient` / `contentLayer` | DOM structure, forms, external scripts, hidden iframes, static JS heuristics. | **0.15** |
| **8. Brand Consistency** | `PageAnalyzerClient` / `contentLayer` | Brand keyword detection vs registered domain mismatch, urgency scoring. | **0.10** |

---

## 3. Database Schema

The Prisma database schema manages relational models:
- **`User` Entity:** Authentication, roles, and analyst credentials.
- **`Analysis` Entity:** Canonical URL, composite risk score, verdict, confidence, `layersJson`, `layerStatusesJson`, `pageStatus`, `pageAnalysisJson`, and human-readable `summary`.
- **`AnalysisEvidence` Entity:** Layer attribution (`URL`, `DOMAIN`, `DNS`, `TLS`, `REPUTATION`, `ML`, `CONTENT`, `FORM`, `BRAND`, `NETWORK`), feature key, severity, and plain-English explanation.
- **`BatchJob` Entity:** Bulk scan job identifier, user reference, total URLs, processed counts, categorized threat stats (Safe, Suspicious, Phishing, Failed), average risk score, and completion timestamp.
- **`BatchItem` Entity:** Individual target URL within a batch job, execution state (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`), verdict, risk score, confidence, and foreign key link to full `Analysis` record.
- **`CommunityReport` Entity:** Crowdsourced indicator submission, target URL, classification type (`PHISHING`, `MALWARE`, `SCAM`, `FALSE_POSITIVE`), description, technical evidence, and analyst moderation status (`PENDING`, `APPROVED`, `REJECTED`, `RESOLVED`).

