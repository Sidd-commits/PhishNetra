# PhishNetra — Complete Enterprise REST API Reference

**Current Version:** `v1.0.0` (Milestone 20 • Complete Multi-Layer Zero-Trust Platform)  
**Base URL:** `http://localhost:5000/api`  
**Authentication Scheme:** Bearer Token (JWT in `Authorization: Bearer <TOKEN>` header)

---

## 1. Authentication & Identity
- **`POST /api/auth/register`**: Creates a new SOC analyst account with name, email, and password.
- **`POST /api/auth/login`**: Authenticates analyst credentials and returns a signed JSON Web Token (JWT).
- **`GET /api/auth/profile`**: Retrieves current authenticated analyst profile and RBAC role.

---

## 2. Real-Time Multi-Layer Threat Analysis
- **`POST /api/analyze`**: Performs synchronous multi-layer inspection on a target URL across lexical heuristics, RDAP domain age, passive DNS, TLS socket handshakes, reputation blacklists, ML inference, and DOM brand consistency.
- **`GET /api/analyze/history`**: Returns paginated historical scans for the authenticated analyst.
- **`GET /api/analyze/:id`**: Retrieves full multi-layer investigation report, evidence items, and layer statuses.

---

## 3. High-Capacity Asynchronous Batch Ingestion
- **`POST /api/batch`**: Submits an array, multiline string, or CSV list of URLs to the asynchronous queue.
- **`GET /api/batch`**: Lists past batch jobs with status and progress telemetry.
- **`GET /api/batch/:id`**: Polls live execution progress, counters, and item-level outcomes.
- **`POST /api/batch/:id/cancel`**: Cancels remaining unexecuted targets in an active batch.
- **`GET /api/batch/:id/export?format=csv|json`**: Exports batch results to downloadable CSV or JSON.

---

## 4. Domain Dossier & Typosquatting Hub
- **`GET /api/domains/:domain`**: Aggregates RDAP age, nameservers, historical scan timeline, and typosquatting threat matrices.
- **`POST /api/domains/typosquatting`**: Generates and inspects simulated typosquatting, Cyrillic homoglyphs, and combosquatting variants.

---

## 5. Threat Graph Infrastructure & Campaign Clustering
- **`GET /api/graph/overview`**: Returns global infrastructure topology graph statistics, top connected nodes, and relationships.
- **`GET /api/graph/domain/:domain`**: Returns k-hop subgraph centered around a target domain.
- **`GET /api/graph/export/stix`**: Exports full infrastructure graph as an OASIS STIX 2.1 JSON bundle.
- **`GET /api/campaigns`**: Lists automatically clustered adversary campaigns with threat rings and IOC sets.
- **`GET /api/campaigns/:id`**: Retrieves single campaign details and STIX 2.1 representation.

---

## 6. MLOps Lifecycle & SHAP Explainability
- **`POST /api/mlops/predict/explain`**: Computes Tree-SHAP local feature attributions, waterfall contributions, and human-readable executive narratives.
- **`GET /api/mlops/models`**: Lists registered models in the registry with performance benchmarks (F1, Precision, Recall, AUC).
- **`POST /api/mlops/models/activate`**: Hot-swaps the active production ML model in memory with zero downtime.
- **`GET /api/mlops/drift/metrics`**: Returns Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) feature drift metrics.
- **`POST /api/mlops/retrain`**: Triggers automated model retraining incorporating new verified samples.
- **`POST /api/mlops/adversarial/test`**: Evaluates classifier resilience against 6 evasion perturbation vectors.

---

## 7. Enterprise SIEM / SOAR & Alert Webhooks
- **`POST /api/siem/export`**: Formats threat analyses into ArcSight CEF, IBM QRadar LEEF, Syslog RFC 5424, Microsoft Sentinel JSON, or Splunk HEC formats.
- **`GET /api/siem/feed`**: Live streaming SIEM event feed.
- **`GET /api/notifications/webhooks`**: Lists registered alert webhooks (Slack, Teams, Discord, PagerDuty, Generic).
- **`POST /api/notifications/webhooks`**: Registers a new alert destination with HMAC-SHA256 signature secret.
- **`POST /api/notifications/test`**: Dispatches a test alert ping to verify webhook delivery.

---

## 8. SOC Case Management & SOAR Playbooks
- **`GET /api/cases`**: Lists active incident cases with severity, status, and assigned analyst.
- **`POST /api/cases`**: Creates a new incident investigation case.
- **`PATCH /api/cases/:id`**: Updates case status, priority, or analyst notes.
- **`GET /api/playbooks`**: Lists pre-configured and custom autonomous defense playbooks.
- **`POST /api/playbooks/:id/execute`**: Executes a SOAR playbook pipeline (DNS sinkholes, firewall blocks, takedown notices).

---

## 9. Red Team Attack Simulation & Benchmarking
- **`GET /api/simulation/presets`**: Returns pre-configured Red Team attack replay scenarios across 12 vector families.
- **`POST /api/simulation/run`**: Simulates attack replay through the Zero-Trust detection pipeline and measures interception layer.
- **`POST /api/simulation/benchmark`**: Executes comprehensive 48-scenario regression benchmark, reporting overall mitigation rate and latency.

---

## 10. Multi-Vector Threat Hunting & Digital Forensics
- **`POST /api/hunting/query`**: Executes threat hunt queries across domain regex, IP CIDR, ASN, JA3 SSL fingerprint, SHA-256 hash, and brand name.
- **`GET /api/hunting/artifact`**: Retrieves deep forensic artifacts (HAR network stream, TLS certificate chain, DOM mutation logs).
- **`GET /api/digital-forensics/artifacts`**: Lists cryptographic digital forensic evidence chains with SHA-256 custody seals.

---

## 11. AI SOC Copilot & Canary Deception
- **`GET /api/copilot/templates`**: Returns SOC prompt templates for triage, reverse engineering, and threat hunt regex.
- **`POST /api/copilot/chat`**: Dispatches analyst query to the AI Copilot reasoning engine for incident analysis.
- **`GET /api/deception/tokens`**: Lists active canary honeypot tokens (1x1 web bugs, DNS tripwires, fake API keys).
- **`POST /api/deception/tokens`**: Generates a new canary honeypot trap with public callback URL.

---

## 12. External Attack Surface Management (EASM)
- **`GET /api/attack-surface/assets`**: Lists perimeter assets (Apex domains, subdomains, ingress IPs, cloud endpoints).
- **`POST /api/attack-surface/assets`**: Registers an enterprise domain or IP block for continuous monitoring.
- **`GET /api/attack-surface/ct-logs`**: Inspects Certificate Transparency (CT) log streams for lookalike brand certificates.

---

## 13. Remote Browser Isolation (RBI) & Phishing Tarpit
- **`GET /api/rbi/sessions`**: Lists active isolated browser sandbox sessions.
- **`POST /api/rbi/sessions`**: Spawns an isolated sandbox session, air-gapping the client from malicious JavaScript.
- **`GET /api/tarpit/tasks`**: Lists active tarpit credential flooding tasks.
- **`POST /api/tarpit/tasks`**: Launches synthetic credential flooding against confirmed phishing kits to exhaust adversary infrastructure.

---

## 14. OASIS TAXII 2.1 Threat Intel Server
- **`GET /api/taxii21/discovery`**: Standard TAXII 2.1 server discovery root serving API information.
- **`GET /api/taxii21/collections`**: Lists available threat intelligence collections.
- **`GET /api/taxii21/collections/:id/objects`**: Retrieves STIX 2.1 indicators and attack patterns from a collection.

---

## 15. AiTM Reverse Proxy & Bayesian Threat Intel Fusion
- **`POST /api/aitm/scan`**: Detects Adversary-in-the-Middle (Evilginx2, Modlishka) proxies, header spoofing, and stolen session cookies.
- **`GET /api/intel-fusion`**: Lists fused threat intelligence indicators with live Bayesian exponential half-life decay.
- **`POST /api/intel-fusion/score`**: Ingests or evaluates an IOC with corroborating source weight boost.

---

## 16. Multimodal Quishing & Threat Actor Attribution
- **`POST /api/quishing/scan`**: Scans QR codes and lure text for malicious embedded redirects and outputs Snort NIDS rules.
- **`GET /api/quishing/samples`**: Returns preset quishing lure samples (MFA Authenticator reset, Microsoft 365 password expiry).
- **`GET /api/attribution/actors`**: Lists cataloged threat actors (e.g., Storm-0837, Midnight Blizzard, Scattered Spider).
- **`POST /api/attribution/match`**: Matches an observed target domain or TTP against adversary profiles.
- **`POST /api/risk-quantification/calculate`**: Executes FAIR quantitative cyber risk modeling with Monte Carlo loss distributions.

---

## 17. Client-Side Anti-Tamper & MITRE D3FEND
- **`POST /api/client-defense/generate`**: Generates obfuscated client-side JavaScript anti-tamper SDK protecting login forms.
- **`POST /api/client-defense/beacon`**: Ingests client tampering alerts (DOM overlay injected, DevTools hook triggered).
- **`POST /api/session-anomaly/evaluate`**: Evaluates continuous user session telemetry for token hijacking and device anomalies.
- **`GET /api/d3fend/matrix`**: Returns MITRE D3FEND countermeasure matrix and mapping.

---

## 18. GenAI Phishing Defense & Telecom Threat Fusion
- **`POST /api/genai-defense/analyze`**: Detects synthetic lure generation, indirect prompt injections, and hidden CSS payloads.
- **`POST /api/telecom-threat/assess`**: Evaluates cross-carrier SMS smishing, sender ID spoofing, and RCS brand misuse.
- **`GET /api/telecom-threat/history`**: Lists historical telecom threat assessments.

---

## 19. BGP Route Hijacking Radar & FIDO2 MFA Guard
- **`POST /api/bgp-integrity/probe`**: Performs autonomous multi-resolver consensus analysis, RPKI ROA verification, and AS path anomaly detection.
- **`GET /api/bgp-integrity/history`**: Lists past BGP routing integrity probes.
- **`POST /api/fido2-guard/probe`**: Verifies WebAuthn `clientDataJSON` cryptographic origin binding and evaluates Passkey immunity against AiTM proxies.
- **`GET /api/fido2-guard/history`**: Lists past FIDO2 MFA evaluations.
- **`GET /api/cti-exchange/stats`**: Returns peer-to-peer CTI exchange metrics, TLP breakdown, and active indicators.

---

## 20. System, Health & Governance
- **`GET /api/health`**: Service health status, database, ML microservice, and cache reachability.
- **`GET /api/metrics`**: Prometheus plain-text metrics format scraper (`HELP` and `TYPE` declarations).
- **`GET /api/system/cache`**: In-memory and persistent cache diagnostics and hit ratios.
- **`GET /api/system/queue`**: Async background worker queue length and worker status.
- **`GET /api/settings/config`**: Dynamic 8-layer risk calibration weights and threshold settings.
- **`GET /api/audit-logs`**: Immutable SOC audit logs with filtering and CSV export.
