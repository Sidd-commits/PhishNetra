# PhishNetra — System Architecture (Milestone 2)

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Current Milestone:** Milestone 2 (Multi-Layer Threat Intelligence)

---

## 1. High-Level Architecture Diagram

```text
                        ┌─────────────────────────────────────────┐
                        │        React SOC Web Dashboard         │
                        │       (apps/web - Vite + Tailwind)      │
                        └────────────────────┬────────────────────┘
                                             │ HTTP / REST + JWT
                                             ▼
                        ┌─────────────────────────────────────────┐
                        │          Node.js Express API            │
                        │               (apps/api)                │
                        └────────────────────┬────────────────────┘
                                             │
                                             ▼
                              URL Canonicalization Engine
                                             │
             ┌──────────────────────┬────────┴────────┬─────────────────────┐
             ▼                      ▼                 ▼                     ▼
     ┌───────────────┐      ┌───────────────┐ ┌───────────────┐     ┌───────────────┐
     │ Layer 1: URL  │      │Layer 2: Domain│ │ Layer 3: DNS  │     │ Layer 4: TLS  │
     │ Intelligence  │      │  Intel & RDAP │ │ & IP Intel    │     │ Intelligence  │
     │ (Lexical/Hex) │      │ (Age Category)│ │ (A/MX/SSRF)   │     │ (Certs/SNI)   │
     └───────┬───────┘      └───────┬───────┘ └───────┬───────┘     └───────┬───────┘
             │                      │                 │                     │
             └──────────────┬───────┴────────┬────────┴─────────────────────┘
                            │                │
                            ▼                ▼
                    ┌───────────────┐ ┌───────────────┐
                    │ Layer 5: Feed │ │ Layer 6: ML   │
                    │  Reputation   │ │ Baseline (RF) │
                    │(URLhaus/Virus)│ │ (FastAPI:8000)│
                    └───────┬───────┘ └───────┬───────┘
                            │                 │
                            └────────┬────────┘
                                     │
                                     ▼
                        ┌─────────────────────────┐
                        │ Multi-Layer Risk Engine │
                        │  (Weighted & Calibrated)│
                        └────────────┬────────────┘
                                     │
                     ┌───────────────┴───────────────┐
                     ▼                               ▼
        Structured Layer Evidence          PostgreSQL / Prisma DB
        (Grouped & Tagged Signals)        (User, Analysis, Evidence)
```

---

## 2. Layer Interfaces & Responsibilities

| Layer | Implementation Class | Responsibilities | Key Outputs |
| :--- | :--- | :--- | :--- |
| **0. Canonicalization** | `canonicalizeUrl` | URL normalization, Punycode IDN conversion, port stripping, case normalization. | `CanonicalUrlResult` |
| **1. URL Intelligence** | `URLLayer` | Structural metrics, Shannon entropy, obfuscated hex `%2F`, shortener detection. | `URLIntelligence` |
| **2. Domain Intelligence** | `DomainLayer` | Registrable domain, public suffix, RDAP gateway querying, domain age in days. | `DomainIntelligence` |
| **3. DNS & IP Intelligence** | `DNSLayer` | Passive DNS lookup (A, AAAA, MX, NS, CNAME), RFC1918 private IP SSRF detection. | `DNSIntelligence` |
| **4. TLS Intelligence** | `TLSLayer` | Non-intrusive TLS socket handshake, certificate validity, expiration, hostname matching. | `TLSIntelligence` |
| **5. Reputation Intelligence** | `ReputationLayer` | Provider abstraction (`URLhausProvider`, `PhishTankProvider`, `VirusTotalProvider`). | `ReputationIntelligence` |
| **6. Machine Learning** | `MLClientService` | Random Forest classifier querying Python microservice on port 8000. | `MLIntelligence` |

---

## 3. Database Schema

The Prisma database schema manages relational models:
- **`User` Entity:** Authentication, roles, and analyst credentials.
- **`Analysis` Entity:** Canonical URL, composite risk score, verdict, confidence, `layersJson`, and `layerStatusesJson`.
- **`AnalysisEvidence` Entity:** Layer attribution (`URL`, `DOMAIN`, `DNS`, `TLS`, `REPUTATION`, `ML`), feature key, severity, and plain-English explanation.
