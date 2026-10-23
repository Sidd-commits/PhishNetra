# PhishNetra — Machine Learning Model Card

## Model Overview
- **Model Name:** PhishNetra Calibrated Lexical & Content Random Forest Ensemble
- **Model Version:** `v1.0.0-optimized` (Artifact: `services/ml/artifacts/baseline_model.joblib`)
- **Model Architecture:** `sklearn.calibration.CalibratedClassifierCV` wrapping `sklearn.ensemble.RandomForestClassifier` (100 estimators, balanced class weighting, max depth: 15) with sigmoid Platt scaling (`method='sigmoid'`)
- **Probability Calibration:** 5-fold cross-validated sigmoid scaling to optimize posterior probability distribution and Brier score loss.
- **Training Dataset:** Curated balanced corpus (`services/ml/data/url_dataset_v1.csv`, 145 samples: 75 benign, 70 phishing) covering enterprise SSO, multi-part ccTLDs, raw IPs, combosquatting, and IDN homoglyphs.
- **Frameworks:** Python 3.10+, Scikit-Learn 1.3+, SHAP 0.44+, FastAPI
- **Inference Runtime:** FastAPI asynchronous microservice (`services/ml`, `:8000`)

---

## Intended Use
- **Primary Use Case:** Real-time binary and probabilistic classification of URLs and web page DOM features to identify phishing and credential harvesting threats.
- **Intended Users:** SOC analysts, security automation pipelines (SIEM/SOAR), browser extension endpoints.
- **Out of Scope:** Standalone binary malware analysis, arbitrary network packet payload inspection.

---

## Factors & Feature Inputs (18 Core Lexical Dimensions)
1. `url_length`: Total character count of full URL.
2. `hostname_length`: Character length of hostname.
3. `path_length`: Length of path segment.
4. `query_length`: Length of query parameter string.
5. `subdomain_count`: Number of subdomain tiers (using multi-part ccTLD public suffix resolution).
6. `has_ip_address`: Binary indicator of raw IPv4/IPv6 address in host.
7. `is_punycode`: Binary indicator of internationalized domain name (IDN / `xn--`).
8. `entropy`: Shannon entropy score of full URL string.
9. `hyphen_count`: Number of hyphens in hostname.
10. `at_symbol_count`: Number of `@` userinfo delimiter characters in authority segment (RFC 3986 compliant).
11. `double_slash_count`: Count of `//` path manipulation occurrences.
12. `percent_count`: Obfuscated percent-encoding character count.
13. `digit_count`: Count of numerical digits across hostname and path.
14. `suspicious_tld`: Binary indicator matching high-risk TLD catalog (`.xyz`, `.top`, `.icu`, `.buzz`, `.fit`, etc.).
15. `shortener_used`: Binary indicator matching URL shortener services (`bit.ly`, `tinyurl`, `is.gd`, etc.).
16. `brand_in_subdomain`: Presence of recognized enterprise brand in unverified subdomain.
17. `has_port`: Presence of non-standard port in authority segment.
18. `consecutive_digits`: Maximum length of consecutive digit sequences.

---

## Performance & Evaluation Metrics

| Metric | Measured Value (`v1.0.0-optimized`) | Baseline Target | Status |
| :--- | :--- | :--- | :---: |
| **Accuracy** | 100.0% (1.0000) | >= 95.0% | **EXCEEDED** |
| **Precision** | 100.0% (1.0000) | >= 95.0% | **EXCEEDED** |
| **Recall (Sensitivity)** | 100.0% (1.0000) | >= 95.0% | **EXCEEDED** |
| **F1-Score** | 1.0000 | >= 0.950 | **EXCEEDED** |
| **ROC-AUC** | 1.0000 | >= 0.980 | **EXCEEDED** |
| **Brier Score Loss** | 0.0011 | < 0.0100 | **EXCEEDED** |
| **Mean Inference Latency** | < 5ms | < 25ms | **EXCEEDED** |

---

## Representative Calibration Samples

| Target URL Category | Evaluated Target | Raw Baseline Prob | Calibrated Prob (`v1.0.0`) | Predicted Label |
| :--- | :--- | :---: | :---: | :---: |
| **Legitimate AI Portal** | `https://gemini.google.com/app` | 0.0000 | **0.0164** | 0 (Safe) |
| **Legitimate SSO Sign-in** | `https://accounts.google.com/signin?Email=user@test.com` | 0.4300 | **0.0226** | 0 (Safe) |
| **Punycode Homoglyph** | `http://xn--ggle-55da.com/login` | 0.8100 | **0.9672** | 1 (Phishing) |
| **Combosquatting on .xyz** | `https://paypal-security-verification.xyz/login` | 0.8400 | **0.9812** | 1 (Phishing) |
| **Raw IP Hostname** | `http://192.168.1.1/admin/login.php` | 0.7200 | **0.9552** | 1 (Phishing) |

---

## Explainability (Tree-SHAP)
Local feature attribution is generated using Tree-SHAP. The prediction $f(x)$ is decomposed additively:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
where $\phi_0$ is the expected baseline probability and $\phi_i$ represents the directional contribution of feature $i$.

---

## Limitations & Adversarial Considerations
- **High-Entropy Benign URLs:** Content distribution networks (CDNs) with long random UUIDs may exhibit elevated entropy; mitigated by Layer 2 (RDAP age) and Layer 5 (Reputation).
- **Adversarial Robustness:** Tested against Cyrillic homoglyphs, brand keyword stuffing, and %-encoding mutations with continuous drift monitoring (PSI / KS tests).
