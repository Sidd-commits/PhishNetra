# PhishNetra — MLOps, Explainability & Retraining Architecture (Milestone 7)

## Overview

Milestone 7 delivers a production-grade **MLOps & Model Intelligence Lifecycle** for the **PhishNetra** zero-trust phishing detection framework. This system operationalizes machine learning models through real-time **SHAP feature attribution**, dynamic **zero-downtime model hot-swapping**, statistical **data/concept drift monitoring (PSI / KS)**, automated **continuous retraining pipelines**, and an **adversarial evasion simulation lab**.

---

## Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                            PhishNetra MLOps Ecosystem                             |
+-----------------------------------------------------------------------------------+
                                       |
    +----------------------------------+-----------------------------------+
    |                                  |                                   |
+---+--------------------+   +---------+--------------+   +----------------+----------------+
|  SHAP Explainability   |   |   Model Registry &     |   |     Data & Concept Drift        |
|     (/predict/explain) |   |    Hot-Swapping        |   |   Monitoring (/drift/metrics)   |
+------------------------+   +------------------------+   +---------------------------------+
| • Exact Tree Path      |   | • Dynamic hot-swap     |   | • Population Stability Index    |
|   attributions         |   | • In-memory activation |   | • Kolmogorov-Smirnov (KS) test  |
| • Additivity guarantee |   | • Metric benchmarking  |   | • Live sample divergence alerts |
| • Executive narrative  |   | • Version cataloging   |   | • Automated retrain triggers    |
+------------------------+   +------------------------+   +---------------------------------+
                                       |
    +----------------------------------+-----------------------------------+
    |                                                                      |
+---+----------------------------------+   +-------------------------------+----------------+
|   Continuous Retraining Pipeline     |   |    Adversarial Hardening & Robustness Lab      |
|             (/retrain)               |   |            (/adversarial/test)                 |
+--------------------------------------+   +------------------------------------------------+
| • Baseline + Honeypot data merge     |   | • Homoglyphs (Cyrillic lookalikes)             |
| • Stratified validation & tuning     |   | • Subdomain packing & brand nesting            |
| • F1-Score auto-promotion threshold  |   | • Keyword stuffing & length inflation          |
| • Zero-downtime registration         |   | • %-Encoding & delimiter obfuscation tricks    |
+--------------------------------------+   +------------------------------------------------+
```

---

## Core Capabilities

### 1. SHAP Feature Attribution (`/predict/explain`)
- **Mathematical Additivity**: Exact path decomposition for decision tree ensembles satisfying:
  $$\mathbb{E}[y] + \sum_{j=1}^M \phi_j = \hat{y}(x)$$
- **Directional Bias**:
  - `PHISHING` ($\phi_j > 0$): Drives model risk upward (e.g. raw IP host, credential keywords, high entropy).
  - `BENIGN` ($\phi_j < 0$): Pulls model risk downward (e.g. HTTPS transport, clean domain structure).
- **Analyst-Ready Executive Narratives**: Auto-synthesized plain English summary explaining the exact structural and lexical causes of the risk rating.

### 2. Model Registry & Zero-Downtime Hot-Swapping (`/models`, `/models/activate`)
- In-memory hot-swapping allows promoting new model weights without restarting microservices or dropping active user requests.
- Version history tracks: Accuracy, Precision, Recall, F1-Score, ROC-AUC, sample size, algorithm type, and artifact path.

### 3. Statistical Data Drift Monitoring (`/drift/metrics`, `/drift/evaluate`)
- **Population Stability Index (PSI)**:
  $$PSI = \sum_{i=1}^k (A_i - E_i) \times \ln\left(\frac{A_i}{E_i}\right)$$
  - $PSI < 0.10 \implies$ `STABLE`
  - $0.10 \le PSI < 0.25 \implies$ `MODERATE`
  - $PSI \ge 0.25 \implies$ `DRIFTED`
- **Kolmogorov-Smirnov (KS) Test**: Evaluates continuous feature distribution distance ($D$-statistic and asymptotic two-sided $p$-value).

### 4. Continuous Retraining Pipeline (`/retrain`)
- Integrates real-world feedback from the SOC Community Threat Reports and verified honeypot feeds.
- Auto-generates version tags, fits balanced class weights, executes cross-validation, and auto-promotes models meeting the configured F1 threshold.

### 5. Adversarial Hardening Lab (`/adversarial/test`)
- Evaluates resistance against 6 cyber evasion tactics:
  1. `HOMOGLYPH`: Unicode Cyrillic lookalike injection.
  2. `KEYWORD_STUFFING`: Dilution using benign path names.
  3. `SUBDOMAIN_PACKING`: Deep SSO prefix nesting.
  4. `TLD_MASQUERADE`: Brand embedding before obscure TLDs.
  5. `LENGTH_INFLATION`: Long query parameter token padding.
  6. `ENCODING_TRICK`: Percent hex hex-escaping.
- Computes per-test score delta, evasion outcome, and overall Robustness Score ($0-100\%$).

---

## API Specifications

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/mlops/explain` | Computes Tree-SHAP local feature attribution and executive narrative summary |
| `GET` | `/api/mlops/models` | Lists all registered models in the registry along with benchmark metrics |
| `GET` | `/api/mlops/models/:version` | Fetches details and metadata for a specific model version |
| `POST` | `/api/mlops/models/activate` | Hot-swaps the active in-memory inference model |
| `GET` | `/api/mlops/drift` | Computes PSI and KS distribution metrics against baseline training corpus |
| `POST` | `/api/mlops/drift/evaluate` | Evaluates feature drift on custom live sample batch |
| `POST` | `/api/mlops/retrain` | Triggers the continuous automated model retraining pipeline |
| `POST` | `/api/mlops/adversarial` | Executes adversarial robustness evaluation suite or test against URL |
