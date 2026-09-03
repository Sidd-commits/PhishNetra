# PhishNetra — Machine Learning Methodology (Milestone 1)

This document outlines the feature engineering theory, baseline classification architecture, evaluation metrics, and dataset standards implemented in Milestone 1.

---

## 1. Feature Engineering Architecture

PhishNetra extracts **18 deterministic URL-level signals** strictly offline without issuing network requests.

### Feature Specification

| Index | Feature Name | Type | Description | Phishing Rationale |
| :---: | :--- | :--- | :--- | :--- |
| 1 | `url_length` | Integer | Total character length of URL | Phishing URLs often use long, nested paths to evade simple filters. |
| 2 | `hostname_length` | Integer | Character length of the host domain | Long hostnames frequently indicate domain spoofing. |
| 3 | `path_length` | Integer | Length of the URL path component | Deep directory paths are common in credential harvesting kits. |
| 4 | `query_length` | Integer | Length of the query parameters | Phishing kits embed tracking tokens and victim emails in query strings. |
| 5 | `subdomain_count` | Integer | Count of subdomain dot levels | Excessive subdomains (e.g. `login.verify.paypal.com.attacker.xyz`) indicate masquerading. |
| 6 | `has_ip_address` | Binary | 1 if host is IPv4/IPv6, else 0 | Attackers use raw IPs when domains are blocked or for fast flux hosting. |
| 7 | `has_https` | Binary | 1 if scheme is https, else 0 | Unencrypted HTTP communication exposes credentials in cleartext. |
| 8 | `special_char_count`| Integer | Count of `@, -, _, =, ?, %, &, !, *, ~` | URL obfuscation techniques utilize special delimiter sequences. |
| 9 | `digit_count` | Integer | Total numeric digits across URL | Generated domains and IP encodings contain high digit ratios. |
| 10| `hyphen_count` | Integer | Hyphens `-` in hostname | Multiple hyphens are widely used in brand typosquatting. |
| 11| `at_symbol_count` | Integer | `@` symbols in URL | `@` can deceive browser parsers into treating prefix text as credentials. |
| 12| `double_slash_in_path`| Binary | 1 if `//` appears inside path | Open redirect or protocol-relative evasion indicator. |
| 13| `encoded_char_count`| Integer | Count of `%` hex-escape sequences | Hex-encoded characters are used to bypass keyword filters. |
| 14| `suspicious_keyword_count`| Integer | Matches against targeted security keywords | Keywords like `login`, `bank`, `verify`, `paypal`, `wallet` in hostname/path. |
| 15| `entropy` | Float | Shannon entropy $H(X)$ of the URL | High randomness indicates hash-based paths or DGA domains. |
| 16| `tld_in_subdomain` | Binary | 1 if known TLD appears in subdomain | e.g., `paypal.com.attacker.com` where `.com` is placed in subdomain. |
| 17| `port_in_url` | Binary | 1 if non-standard explicit port used | Explicit ports (e.g. `:8080`, `:8443`) are anomalous on consumer auth pages. |
| 18| `tld_length` | Integer | Character length of top-level domain | Unusually long or novel generic TLDs. |

### Mathematical Formulation: Shannon Character Entropy

Shannon entropy measures the uncertainty / information density of character distribution in the URL:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where $P(x_i)$ is the relative frequency of character $x_i$ in the URL string of length $N$:

$$P(x_i) = \frac{\text{count}(x_i)}{N}$$

---

## 2. Baseline Model Architecture

- **Algorithm:** `RandomForestClassifier` (Ensemble of 100 decision trees, `max_depth=6`, balanced class weighting).
- **Serialization:** Model artifact serialized with `joblib` into `services/ml/artifacts/baseline_model.joblib`.
- **Inference Latency:** Sub-5ms per URL.

---

## 3. Training & Evaluation Pipeline

The pipeline is reproducible via:

```bash
python services/ml/training/train.py --data services/ml/data/synthetic_sample.csv --output services/ml/artifacts
```

Evaluation metrics are serialized to `services/ml/artifacts/metrics.json` and include:
- Precision, Recall, F1 Score
- ROC-AUC
- Confusion Matrix (True Positives, False Positives, True Negatives, False Negatives)
- Feature Importance ranking

---

## 4. Ground-Truth Data & Integrity Policy

In accordance with strict cybersecurity research ethics:
- No artificial real-world datasets are fabricated.
- The repository includes a deterministic synthetic dataset fixture (`services/ml/data/synthetic_sample.csv`) explicitly labeled as synthetic development data for CI/CD and pipeline validation.
- Instructions for ingesting genuine threat feeds (e.g. PhishTank, Tranco, URLhaus) are provided in `services/ml/data/README.md`.
