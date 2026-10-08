# ADR 0003: Tree-SHAP Feature Attribution & Local Explainability

## Status
**Accepted**

## Context
Black-box Machine Learning models create operational friction for SOC analysts. When a classifier outputs a high risk score without explanation, analysts cannot determine whether the decision is driven by legitimate anomalies or spurious correlations.

## Decision
We integrated Tree-SHAP (SHapley Additive exPlanations) into the Python ML inference microservice (`explainability.py`):
1. **Additive Feature Attribution:**
   - Computes exact Shapley values for tree-based ensembles (Random Forest / Gradient Boosting).
   - Satisfies the mathematical properties of Local Accuracy, Missingness, and Consistency.
2. **Directional & Narrative Synthesis:**
   - Decomposes predictions into base value $E[f(x)]$ plus positive (risk-increasing) and negative (risk-decreasing) feature contributions.
   - Generates automated human-readable technical explanations for each feature (e.g., "High Shannon entropy (4.82) indicates heavily obfuscated URL structure").
3. **Structured API Contract:**
   - Exposes attribution metrics via `POST /predict/explain` and `POST /api/mlops/explain` for frontend charting.

## Consequences
- **Positive:** Enables instant SOC triage and forensic auditability.
- **Positive:** Identifies feature importance shifts and potential bias during model retraining.
- **Trade-off:** SHAP computation adds ~20-50ms per explanation request; managed via on-demand computation rather than blocking baseline inference.
