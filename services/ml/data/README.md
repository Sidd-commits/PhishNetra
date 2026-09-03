# PhishNetra — ML Dataset Guide (Milestone 1)

## Purpose & Data Policy

This directory documents the data contracts, dataset formats, and preprocessing standards for PhishNetra's Machine Learning detection pipeline.

> **CRITICAL NOTE ON DATASETS (MILESTONE 1 RULE):**  
> In accordance with the project integrity principles, **no fabricated real-world datasets are represented as genuine empirical threat feeds**.  
> The repository includes `synthetic_sample.csv`, which is **strictly a deterministic synthetic development fixture** designed to validate the end-to-end feature extraction, cross-validation, serialization, and FastAPI inference pipeline.

---

## 1. Expected Dataset Format

When importing external phishing corpora (such as [PhishTank](https://phishtank.org/), [URLhaus](https://urlhaus.abuse.ch/), [ISCX-URL-2016](https://www.unb.ca/cic/datasets/url-2016.html), or [Alexa Top 1M / Tranco Top 1M](https://tranco-list.eu/)), the raw dataset must adhere to the following schema:

| Column Name | Data Type | Permitted Values | Description |
| :--- | :--- | :--- | :--- |
| `url` | String (UTF-8) | Valid RFC-compliant URL string | Complete URL including scheme (e.g. `http://...` or `https://...`) |
| `label` | Integer | `0` or `1` | Ground-truth classification: `0` for Legitimate/Safe, `1` for Phishing/Malicious |
| `source` | String (Optional) | e.g. `phishtank`, `tranco`, `synthetic` | Origin data feed identifier for lineage tracking |
| `added_date` | String (Optional) | ISO 8601 Timestamp | Timestamp when the indicator was harvested |

---

## 2. Preprocessing & Hygiene Standards

1. **Deduplication:** URLs must be deduplicated after canonicalization (`scheme://hostname/path?query`).
2. **Class Balance:** Production training datasets should maintain a realistic 1:1 or 1:2 ratio of phishing to legitimate URLs to avoid severe class imbalance skew during baseline training.
3. **SSRF Guard:** Data ingestion routines must never execute HTTP GET requests against candidate URLs during offline training. All extraction in Milestone 1 operates strictly on offline URL lexical and syntactic structures.

---

## 3. Directory Layout

```text
services/ml/data/
├── README.md                 # Dataset documentation (this file)
└── synthetic_sample.csv      # Synthetic baseline training fixture (clearly marked)
```
