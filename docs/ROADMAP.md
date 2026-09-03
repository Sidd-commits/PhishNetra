# PhishNetra — 10-Month Master Roadmap

**Project Title:** PhishNetra — A MultiLayered AI-Driven Zero-Trust Framework for Real-Time Phishing Detection and Browser-Level Threat Mitigation  
**Timeline:** 10 Months (8 Major Milestones)

---

## Milestone 1 — Months 1 → 1.5 (COMPLETED)
**Core Foundation & Working Prototype**
- [x] Monorepo structure (`apps/web`, `apps/api`, `services/ml`, `packages/shared`, `prisma/`)
- [x] PostgreSQL database schema with Prisma ORM
- [x] User registration, login, logout, bcrypt hashing, and JWT authentication
- [x] Deterministic 18+ URL feature extraction engine
- [x] Baseline Machine Learning classification pipeline (Random Forest)
- [x] Composite Risk Engine (ML + rule-based heuristic scoring)
- [x] Structured evidence synthesis and human-readable analyst explanations
- [x] React 18 + Vite + Tailwind CSS SOC web dashboard
- [x] Automated unit and integration test suites (Jest + Pytest)
- [x] Architectural, API, ML, and Security documentation

---

## Milestone 2 — Months 2 → 3
**Domain Intelligence, Network Telemetry & Reputation Integrations**
- [ ] Passive DNS resolution (A, AAAA, MX, NS, TXT, SOA record inspection)
- [ ] TLS/SSL Certificate Analyzer (validity period, issuer trust, SAN mismatch, Let's Encrypt vs OV/EV)
- [ ] WHOIS / RDAP intelligence (domain creation date, registrar age, privacy proxy detection)
- [ ] Reputation API integrations (URLhaus, PhishTank, Google Safe Browsing, VirusTotal)
- [ ] Typosquatting & Homoglyph Engine (Levenshtein distance, Unicode confusable detection for top 500 brands)
- [ ] Advanced brand impersonation detection rules

---

## Milestone 3 — Months 3 → 5
**Secure Page Analyzer, DOM Feature Extraction & SHAP Explainability**
- [ ] SSRF-isolated sandbox worker container for safe webpage fetching
- [ ] Headless browser instrumentation (Playwright) for dynamic redirect chain analysis
- [ ] DOM & Content Feature Extractor (fake login forms, external form actions, hidden iframe detection, zero-link anchors)
- [ ] Logo visual similarity matching & favicon hashing
- [ ] SHAP (SHapley Additive exPlanations) integration for feature importance attribution
- [ ] Gradient Boosting (XGBoost / LightGBM) model upgrade and probability calibration

---

## Milestone 4 — Months 5 → 6
**Distributed Asynchronous Architecture & High-Throughput Ingestion**
- [ ] Redis caching layer for fast reputation and URL verdicts
- [ ] BullMQ job orchestration for asynchronous heavy page analysis
- [ ] Batch URL scanning API (CSV upload and parallel execution)
- [ ] Webhook notification system for external SIEM/SOAR triggers
- [ ] Worker auto-scaling and resilience policies

---

## Milestone 5 — Months 6 → 7
**Manifest V3 Browser Extension & Real-Time Client Mitigation**
- [ ] Chrome / Edge Manifest V3 extension
- [ ] Service worker active tab URL monitoring
- [ ] Inline risk badge and interactive popup investigation view
- [ ] Full-screen interstitial phishing block warning with override controls
- [ ] Client-side pre-filtering heuristic engine for ultra-low latency alerts

---

## Milestone 6 — Months 7 → 8
**Threat Intelligence Graph, Analyst Workflows & Community Reporting**
- [ ] Graph-based relationship explorer (Domain -> IP -> Certificate -> Campaign)
- [ ] Community threat reporting & false positive appeal workflow
- [ ] Role-Based Access Control (RBAC) with Analyst, Investigator, and Admin roles
- [ ] Analyst investigation notes, tagging, and forensic export (PDF/JSON)
- [ ] Historical phishing campaign clustering

---

## Milestone 7 — Months 8 → 9
**MLOps Pipeline, Adversarial Hardening & Observability**
- [ ] Automated model retraining pipelines with MLflow and DVC
- [ ] Concept drift & data drift monitoring
- [ ] Adversarial robustness testing (evasion attacks, randomized subdomains, encoded paths)
- [ ] Structured logging with Prometheus metrics and Grafana dashboards
- [ ] Distributed tracing with OpenTelemetry

---

## Milestone 8 — Months 9 → 10
**Production Hardening, Benchmarking & Final Demonstration**
- [ ] End-to-end performance benchmarking and latency optimization (<50ms target)
- [ ] Comprehensive security audit, penetration testing, and vulnerability remediation
- [ ] Kubernetes / Helm deployment configurations with high availability
- [ ] Final UI/UX polish and interactive demo data suites
- [ ] Final project defense documentation and comprehensive thesis report
