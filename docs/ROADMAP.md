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
| **Milestone 7** | Month 8 → 9 | MLOps Lifecycle, Continuous Retraining, Model Registry & Adversarial Hardening | **COMPLETED** |
| **Milestone 8** | Month 9 → 10 | Enterprise SIEM/SOAR Deployment, Latency Optimization (<250ms), Final Benchmarking | Planned |

---

## Implementation 7 Deliverables Summary
1. **SHAP Feature Attribution & Local Explainability Engine (`explainability.py` / `/predict/explain`):** Exact Tree-SHAP additive feature attributions with guaranteed mathematical efficiency, directional risk bias (+/-), and plain English narrative synthesis.
2. **Model Registry & Dynamic Hot-Swapping (`registry.py` / `/models`, `/models/activate`):** In-memory zero-downtime hot-swapping, performance benchmark tracking (Accuracy, Precision, Recall, F1, ROC-AUC), and active production promotion.
3. **Data & Concept Drift Monitoring Engine (`drift_detector.py` / `/drift/metrics`):** Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) two-sample divergence tests across all 18 URL features with automated retrain recommendation triggers.
4. **Continuous Automated Retraining Pipeline (`retrain_pipeline.py` / `/retrain`):** Integrates baseline corpora with newly verified honeypot/community submissions, fits balanced class weights, executes cross-validation, and auto-promotes models meeting the configured F1 threshold.
5. **Adversarial Hardening Lab (`adversarial.py` / `/adversarial/test`):** Tests classifier evasion resistance across 6 perturbation vectors (Unicode Cyrillic homoglyphs, brand keyword stuffing, subdomain packing, TLD masquerading, length inflation, and %-encoding tricks) with scorecard generation.
6. **Express API Integration (`apps/api/src/routes/mlops.ts` & `MLOpsService.ts`):** Complete proxying and coordination with the Python ML microservice.
7. **React SOC MLOps Console (`MLOpsPage.tsx` / `/mlops`):** Tabbed SOC dashboard with interactive SHAP explainer bar charts, model registry cards with 1-click activation, real-time PSI drift meters, and live adversarial simulation workbench.
8. **129 Automated Tests Passing:** 59 Jest API tests across 14 suites, 12 Jest Extension tests, 58 Pytest ML tests.

---

## Future Milestone 8 Preview (Next Milestone)
* **Enterprise SIEM/SOAR Integrations:** Splunk, Elastic SIEM, Microsoft Sentinel, IBM QRadar connectors.
* **Real-Time Notification Channels:** Slack, MS Teams, PagerDuty, Discord webhooks.
* **Low-Latency Production Optimization:** Sub-250ms distributed execution pipeline and final benchmarking.



