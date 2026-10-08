# PhishNetra — Machine Learning Model Card

## Model Overview
- **Model Name:** PhishNetra Lexical & Content Random Forest Ensemble
- **Model Version:** `v0.1.0-baseline`
- **Model Architecture:** `sklearn.ensemble.RandomForestClassifier` (100 estimators, balanced class weighting, max depth: 15)
- **Frameworks:** Python 3.10+, Scikit-Learn 1.3+, SHAP 0.44+
- **Inference Runtime:** FastAPI asynchronous microservice (`services/ml`)

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
5. `subdomain_count`: Number of subdomain tiers.
6. `has_ip_address`: Binary indicator of raw IP in host.
7. `is_punycode`: Binary indicator of internationalized domain name (IDN).
8. `entropy`: Shannon entropy score of full URL string.
9. `hyphen_count`: Number of hyphens in hostname.
10. `at_symbol_count`: Number of `@` userinfo delimiter characters.
11. `double_slash_count`: Count of `//` path manipulation occurrences.
12. `percent_count`: Obfuscated percent-encoding character count.
13. `digit_count`: Count of numerical digits across hostname and path.
14. `suspicious_tld`: Binary indicator matching high-risk TLD catalog.
15. `shortener_used`: Binary indicator matching URL shortener services (`bit.ly`, `tinyurl`).
16. `brand_in_subdomain`: Presence of recognized enterprise brand in subdomain.
17. `has_port`: Presence of non-standard port in authority segment.
18. `consecutive_digits`: Maximum length of consecutive digit sequences.

---

## Performance & Evaluation Metrics

| Metric | Measured Value (Test Split) | Baseline Target |
| :--- | :--- | :--- |
| **Accuracy** | 97.4% | >= 95.0% |
| **Precision** | 96.8% | >= 95.0% |
| **Recall (Sensitivity)** | 98.1% | >= 95.0% |
| **F1-Score** | 0.974 | >= 0.950 |
| **ROC-AUC** | 0.992 | >= 0.980 |
| **Mean Inference Latency** | < 12ms | < 25ms |

---

## Explainability (Tree-SHAP)
Local feature attribution is generated using Tree-SHAP. The prediction $f(x)$ is decomposed additively:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$
where $\phi_0$ is the expected baseline probability and $\phi_i$ represents the directional contribution of feature $i$.

---

## Limitations & Adversarial Considerations
- **High-Entropy Benign URLs:** Content distribution networks (CDNs) with long random UUIDs may exhibit elevated entropy; mitigated by Layer 2 (RDAP age) and Layer 5 (Reputation).
- **Adversarial Robustness:** Tested against Cyrillic homoglyphs, brand keyword stuffing, and %-encoding mutations with continuous drift monitoring (PSI / KS tests).
