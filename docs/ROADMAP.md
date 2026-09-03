# PhishNetra — 10-Month Master Roadmap

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Specification Reference:** `/Markdowns/02_AI_IDE_MASTER_PROMPT.md`

---

## Roadmap Milestones

| Milestone | Timeframe | Focus Area | Status |
| :--- | :--- | :--- | :---: |
| **Milestone 1** | Month 1 → 1.5 | Architecture Foundation, Deterministic Features, Baseline ML, Web Console | **COMPLETED** |
| **Milestone 2** | Month 1.5 → 3 | Multi-Layer Intelligence (RDAP, DNS, TLS, Reputation Feeds, Risk Engine) | **COMPLETED** |
| **Milestone 3** | Month 3 → 5 | Sandboxed Web Page Crawler, DOM/HTML Features, Visual Phishing & SHAP | Planned |
| **Milestone 4** | Month 5 → 6 | Async Worker Architecture (BullMQ, Redis), Caching & Batch Ingestion | Planned |
| **Milestone 5** | Month 6 → 7 | Chrome Manifest V3 Browser Extension & Real-Time Threat Blocking | Planned |
| **Milestone 6** | Month 7 → 8 | Threat Graph Engine, IOC Clustering & Analyst Intelligence Explorer | Planned |
| **Milestone 7** | Month 8 → 9 | MLOps Lifecycle, Continuous Retraining, Model Registry & Adversarial Hardening | Planned |
| **Milestone 8** | Month 9 → 10 | Enterprise Deployment, Latency Optimization (<250ms), Final Benchmarking | Planned |

---

## Milestone 2 Deliverables Summary
1. Dedicated URL Canonicalization module.
2. Layer 1: Enhanced URL Intelligence & Obfuscation Detection.
3. Layer 2: Domain Intelligence with RDAP age categorization.
4. Layer 3: Passive DNS and IP intelligence with RFC1918 SSRF blocking.
5. Layer 4: Non-intrusive TLS handshake inspection and Zero-Trust validation.
6. Layer 5: Reputation threat feed abstraction with provider resilience.
7. Multi-Layer Risk Engine with configurable weighting and dynamic rebalancing.
8. Enhanced React SOC Dashboard with multi-layer breakdown cards and layer-filtered evidence.
9. 37 automated tests across Python and Node.js.
