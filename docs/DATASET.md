# PhishNetra — Dataset Specification & Governance

## 1. Dataset Overview

The training, evaluation, and drift monitoring datasets used by PhishNetra are compiled from curated open-source cybersecurity intelligence feeds and verified benign internet top-lists.

---

## 2. Data Sources & Composition

| Source | Category | Label | Description |
| :--- | :--- | :--- | :--- |
| **Tranco Top 1M / Majestic Million** | Benign | `0` (Legitimate) | Top 100,000 highly ranked enterprise, academic, and commercial domains. |
| **URLhaus Live Database (abuse.ch)** | Malicious | `1` (Phishing/Malware) | Active malware distribution and credential harvesting URLs. |
| **OpenPhish Community Feed** | Malicious | `1` (Phishing) | Real-time verified zero-day phishing target URLs. |
| **PhishTank Database** | Malicious | `1` (Phishing) | Crowdsourced and human-verified phishing submissions. |
| **PhishNetra Honeypot & Analyst Submissions** | Mixed | Verified | Community submissions vetted through SOC analyst moderation. |

---

## 3. Data Preprocessing & Canonicalization

Before feature extraction or model training, all URLs undergo deterministic canonicalization:
1. **Scheme Lowercasing**: `HTTP://` / `hTtPs://` normalized to `http://` / `https://`.
2. **Punycode / IDN Conversion**: Unicode hostnames (`xn--...`) decoded to ensure accurate homoglyph and character set inspection.
3. **Port Normalization**: Standard ports `:80` and `:443` stripped; custom ports preserved as features.
4. **Delimiter & Slash Normalization**: Redundant consecutive slashes (`//`) collapsed.

---

## 4. Train / Validation / Test Splitting

- **Training Split (70%):** Used for fitting Random Forest decision trees with stratified 5-fold cross-validation.
- **Validation Split (15%):** Used for hyperparameter tuning and threshold calibration ($0.50 \to 0.70$ high-confidence boundary).
- **Test Split (15%):** Held-out dataset evaluated for precision, recall, ROC-AUC, and adversarial perturbation resilience.

---

## 5. Drift Monitoring & Retraining Triggers

Production inference feature distributions are monitored continuously using two statistical divergence tests:
- **Population Stability Index (PSI):** Quantifies distributional shift across binned features ($PSI > 0.25$ indicates critical drift).
- **Kolmogorov-Smirnov (KS) Test:** Non-parametric two-sample test measuring maximum cumulative distribution divergence ($p < 0.05$).

When significant drift is detected across $>3$ core features, the automated retraining pipeline (`retrain_pipeline.py`) is triggered.
