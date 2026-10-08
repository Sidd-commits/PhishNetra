# PhishNetra — 10-Month Master Roadmap

**Project:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Specification Reference:** `/Markdowns/02_AI_IDE_MASTER_PROMPT.md`

---

## Roadmap Milestones

| Milestone | Timeframe | Focus Area | Status |
| :--- | :--- | :--- | :---: |
| **Milestone 1** | Month 1 → 1.5 | Architecture Foundation, Deterministic Features, Baseline ML, Web Console | **COMPLETED** |
| **Milestone 2** | Month 1.5 → 3 | Multi-Layer Intelligence (RDAP, DNS, TLS, Reputation Feeds, Risk Engine) | **COMPLETED** |
| **Milestone 3 / Implementation 3** | Month 3 → 5 | Secure Web Content Analysis, Isolated Browser Sandbox, DOM/Form/Brand Analysis | **COMPLETED** |
| **Milestone 4 / Implementation 4** | Month 5 → 6 | Async Worker Architecture (BullMQ, Redis), Caching & Batch Ingestion, Domain Dossier | **COMPLETED** |
| **Milestone 5** | Month 6 → 7 | Chrome Manifest V3 Browser Extension & Real-Time Threat Mitigation | **COMPLETED** |
| **Milestone 6** | Month 7 → 8 | Threat Graph Engine, IOC Clustering & Analyst Intelligence Explorer | **COMPLETED** |
| **Milestone 7** | Month 8 → 9 | MLOps Lifecycle, Continuous Retraining, Model Registry & Adversarial Hardening | Planned |
| **Milestone 8** | Month 9 → 10 | Enterprise Deployment, Latency Optimization (<250ms), Final Benchmarking | Planned |

---

## Implementation 6 Deliverables Summary
1. **Threat Graph Engine (`ThreatGraphEngine.ts`):** Multi-entity graph modeling (`DOMAIN`, `IP`, `ASN`, `CERTIFICATE`, `NAMESERVER`, `REGISTRAR`, `BRAND`, `CAMPAIGN`) and 10 relationship edge types.
2. **Sub-Graph Traversal & Co-Location Engine:** Real-time k-hop neighborhood expansion, co-location discovery, and automatic ingestion from multi-layer scan results.
3. **Autonomous Threat Campaign Clustering (`CampaignClusteringEngine.ts`):** Multi-factor infrastructure correlation matrix (shared ASNs, nameservers, targeted brands, IP subnets, TLS certs) automatically forming named threat rings.
4. **OASIS STIX 2.1 Threat Sharing (`STIXExportService.ts`):** Complete STIX 2.1 JSON bundle exporter for campaigns, identities, indicators, and observable relationships.
5. **Interactive React SOC Graph Explorer (`/graph`):** Force-directed SVG physics visualizer with zoom/pan, node dragging, halo glows, and inspector side drawer.
6. **Threat Campaign & Intrusion Set Console (`/campaigns`):** Dedicated campaign monitoring hub with IOC matrices, STIX export buttons, and search filters.
7. **111 Automated Tests Passing:** 55 Jest API tests across 13 suites, 12 Jest Extension tests, 44 Pytest ML tests.

---

## Future Milestone 7 Preview (Next Milestone)
* **MLOps Lifecycle & Continuous Retraining:** Automated dataset collection, model drift monitoring, SHAP explainability, and artifact registry.
* **Adversarial Hardening:** Robustness testing against evasive homoglyphs and polymorphic phishing templates.


