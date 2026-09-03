# PhishNetra — Machine Learning Methodology & Multi-Layer Integration

**Milestone:** Milestone 2 (Multi-Layer Threat Intelligence)  
**Model Version:** `v0.1.0-baseline`

---

## 1. Role of ML in the Multi-Layer Architecture

In PhishNetra Milestone 2, the Machine Learning classifier is an **independent intelligence layer (Layer 6)** rather than the sole decision-maker.

- **Weight in Multi-Layer Risk Engine:** 20%
- **Feature Vector:** 18 deterministic lexical, structural, and information-theoretic signals.
- **Model Classifier:** `RandomForestClassifier` (100 estimators, max depth 6, balanced class weights).
- **Latency:** Sub-2ms per prediction.

---

## 2. Preventing Double Counting Between Rules and ML

Because some features (e.g. `has_ip_address`, `entropy`, `suspicious_keyword_count`) are evaluated both by the ML model and rule heuristics, the Multi-Layer Risk Engine assigns explicit normalized weights to each layer and caps individual rule contributions.

```text
Layer Weights:
• URL Intelligence:      20%
• Domain Intelligence:   15%
• DNS Intelligence:      10%
• TLS Intelligence:      10%
• Reputation Feeds:      25%
• ML Classifier:         20%
```

If the ML probability indicates a high threat ($\ge 70\%$), a dedicated `ML` layer evidence item is generated to provide transparency into model contribution.
