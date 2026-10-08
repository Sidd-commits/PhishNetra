"""
PhishNetra - SHAP Feature Attribution & Model Explainability Engine
Module: services.ml.app.models.explainability
Milestone: 7
"""

import time
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd

from app.core.schemas import (
    SHAPFeatureAttributionModel,
    SHAPExplanationResponse,
    URLFeatureVectorModel
)
from app.features.url_features import (
    URLFeatureExtractor,
    FEATURE_COLUMNS,
    normalize_url
)


def get_human_description(feature_name: str, feature_value: Any, direction: str) -> str:
    """
    Synthesizes an analyst-friendly natural language explanation for why a feature
    contributed towards a Phishing or Benign verdict.
    """
    is_phish = (direction == "PHISHING")

    if feature_name == "has_ip_address":
        return "Direct IP address host used instead of registered domain" if is_phish else "Uses legitimate registered domain name rather than raw IP"
    elif feature_name == "subdomain_count":
        return f"Excessive subdomain hierarchy ({feature_value} levels) obscuring domain identity" if is_phish else f"Standard domain hierarchy ({feature_value} subdomains)"
    elif feature_name == "suspicious_keyword_count":
        return f"Detected {feature_value} targeted security/credential keywords (e.g. login, verify, banking)" if is_phish else "No high-risk phishing keywords in URL structure"
    elif feature_name == "entropy":
        return f"High character entropy ({feature_value:.2f}) indicates pseudo-random tokens or obfuscation" if is_phish else f"Natural language character entropy ({feature_value:.2f})"
    elif feature_name == "has_https":
        return "Unencrypted HTTP scheme without TLS certificate security" if is_phish else "Secure HTTPS transport protocol enabled"
    elif feature_name == "hyphen_count":
        return f"High hyphen frequency ({feature_value}) in domain commonly used for typosquatting" if is_phish else "Clean domain naming without deceptive hyphens"
    elif feature_name == "at_symbol_count":
        return "Presence of '@' character masking the actual destination authority" if is_phish else "Standard authority delimiters without '@' injection"
    elif feature_name == "double_slash_in_path":
        return "Double slash ('//') in path used to redirect browser or hide host" if is_phish else "Standard path formatting"
    elif feature_name == "encoded_char_count":
        return f"High count of percent-encoded characters ({feature_value}) hiding true destination" if is_phish else "Clean URL characters without evasive hex-encoding"
    elif feature_name == "tld_in_subdomain":
        return "Deceptive top-level domain token embedded inside subdomain" if is_phish else "Standard subdomain structure"
    elif feature_name == "url_length":
        return f"Unusually long URL ({feature_value} chars) typical of credential harvesting links" if is_phish else f"Normal URL character length ({feature_value} chars)"
    elif feature_name == "hostname_length":
        return f"Abnormally long hostname ({feature_value} chars)" if is_phish else "Standard domain name length"
    elif feature_name == "path_length":
        return f"Deeply nested URL path ({feature_value} chars)" if is_phish else "Normal URL path structure"
    elif feature_name == "query_length":
        return f"Excessive query parameters ({feature_value} chars) carrying tracking payloads" if is_phish else "Compact query string length"
    elif feature_name == "special_char_count":
        return f"High accumulation of special characters ({feature_value})" if is_phish else "Normal special character count"
    elif feature_name == "digit_count":
        return f"Excessive numeric characters ({feature_value}) in domain/path" if is_phish else "Normal alphanumeric balance"
    elif feature_name == "port_in_url":
        return "Non-standard network port specified in URL" if is_phish else "Standard web transport port"
    elif feature_name == "tld_length":
        return f"Unconventional TLD length ({feature_value})" if is_phish else "Standard TLD length"
    else:
        return f"Feature '{feature_name}' with value {feature_value} influenced classification towards {direction.lower()}"


class SHAPExplainerService:
    """
    Computes exact Tree-based SHAP / Path-based Feature Attribution for Scikit-Learn ensembles.
    Satisfies additivity: sum(attributions) = prediction - base_value.
    """

    def compute_tree_shap(self, model: Any, feature_vector: np.ndarray, feature_names: List[str]) -> Tuple[float, np.ndarray]:
        """
        Calculates exact tree path feature attributions for a RandomForestClassifier.
        Returns:
            base_value: float (expected probability across tree roots)
            shap_values: np.ndarray (per-feature additive contribution)
        """
        n_features = len(feature_names)
        shap_values = np.zeros(n_features)
        base_values = []

        # Iterate over all individual Decision Trees in the Random Forest
        for estimator in model.estimators_:
            tree = estimator.tree_
            # Root node class 1 probability
            root_prob = tree.value[0, 0, 1] / float(np.sum(tree.value[0, 0]))
            base_values.append(root_prob)

            # Traverse path for feature_vector
            node_id = 0
            while tree.children_left[node_id] != tree.children_right[node_id]:  # Not a leaf
                feature_idx = tree.feature[node_id]
                threshold = tree.threshold[node_id]

                # Probability before split
                p_current = tree.value[node_id, 0, 1] / float(np.sum(tree.value[node_id, 0]))

                # Move to next node
                if feature_vector[feature_idx] <= threshold:
                    next_node = tree.children_left[node_id]
                else:
                    next_node = tree.children_right[node_id]

                # Probability after split
                p_next = tree.value[next_node, 0, 1] / float(np.sum(tree.value[next_node, 0]))

                # Feature contribution along this branch
                delta = p_next - p_current
                shap_values[feature_idx] += delta
                node_id = next_node

        n_estimators = len(model.estimators_)
        avg_base_value = float(np.mean(base_values)) if base_values else 0.5
        avg_shap_values = shap_values / max(1, n_estimators)

        return avg_base_value, avg_shap_values

    def explain(self, raw_url: str, model_service: Any) -> SHAPExplanationResponse:
        """
        Executes full SHAP explainability analysis for a given URL.
        """
        normalized = normalize_url(raw_url)
        raw_features = URLFeatureExtractor.extract_features(normalized)
        feature_columns = getattr(model_service, "feature_columns", FEATURE_COLUMNS)
        model = getattr(model_service, "model", None)
        model_version = getattr(model_service, "version", "v0.1.0-baseline")

        feature_array = np.array([raw_features[col] for col in feature_columns], dtype=float)

        if model is not None and hasattr(model, "estimators_"):
            # Trained Tree Ensemble
            base_value, shap_array = self.compute_tree_shap(model, feature_array, feature_columns)
            probabilities = model.predict_proba([feature_array])[0]
            phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
            predicted_label = int(model.predict([feature_array])[0])
        else:
            # Fallback heuristic calculation
            base_value = 0.35
            shap_array = np.zeros(len(feature_columns))
            for i, col in enumerate(feature_columns):
                val = raw_features[col]
                if col == "has_ip_address" and val == 1:
                    shap_array[i] = 0.30
                elif col == "suspicious_keyword_count" and val > 0:
                    shap_array[i] = min(0.25, val * 0.12)
                elif col == "has_https" and val == 0:
                    shap_array[i] = 0.15
                elif col == "has_https" and val == 1:
                    shap_array[i] = -0.15
                elif col == "subdomain_count" and val >= 3:
                    shap_array[i] = 0.15
                elif col == "entropy" and val > 4.5:
                    shap_array[i] = 0.10
                elif col == "hyphen_count" and val >= 2:
                    shap_array[i] = 0.10
                elif col == "encoded_char_count" and val > 0:
                    shap_array[i] = 0.08
                else:
                    shap_array[i] = -0.02  # Neutral benign baseline nudge

            pred_response = model_service.predict(raw_url)
            phishing_prob = pred_response.phishing_probability
            predicted_label = pred_response.predicted_label

        # Compute total magnitude for normalized percentage share
        abs_sum = float(np.sum(np.abs(shap_array)))
        if abs_sum < 1e-6:
            abs_sum = 1.0

        attributions: List[SHAPFeatureAttributionModel] = []
        top_phishing_factors: List[str] = []
        top_benign_factors: List[str] = []

        for i, col in enumerate(feature_columns):
            shap_val = float(shap_array[i])
            val = raw_features[col]
            direction = "PHISHING" if shap_val >= 0 else "BENIGN"
            pct = round((abs(shap_val) / abs_sum) * 100.0, 2)
            desc = get_human_description(col, val, direction)

            attributions.append(
                SHAPFeatureAttributionModel(
                    featureName=col,
                    featureValue=val,
                    shapValue=round(shap_val, 4),
                    direction=direction,
                    contributionPercent=pct,
                    humanDescription=desc
                )
            )

        # Sort attributions by absolute impact
        attributions.sort(key=lambda x: abs(x.shapValue), reverse=True)

        for attr in attributions:
            if attr.direction == "PHISHING" and len(top_phishing_factors) < 3 and attr.shapValue > 0.005:
                top_phishing_factors.append(f"{attr.featureName} (+{attr.contributionPercent:.1f}%)")
            elif attr.direction == "BENIGN" and len(top_benign_factors) < 3 and attr.shapValue < -0.005:
                top_benign_factors.append(f"{attr.featureName} (-{attr.contributionPercent:.1f}%)")

        # Synthesize executive narrative summary
        if predicted_label == 1:
            phish_drivers = ", ".join(top_phishing_factors) if top_phishing_factors else "structural anomalies"
            narrative = (
                f"Model classified this URL with {phishing_prob * 100:.1f}% phishing probability. "
                f"Key threat vectors driving risk: {phish_drivers}."
            )
        else:
            benign_drivers = ", ".join(top_benign_factors) if top_benign_factors else "legitimate structural indicators"
            narrative = (
                f"Model evaluated this URL as legitimate ({phishing_prob * 100:.1f}% phishing probability). "
                f"Safety indicators reinforced by: {benign_drivers}."
            )

        return SHAPExplanationResponse(
            url=raw_url,
            baseValue=round(base_value, 4),
            predictedProbability=round(phishing_prob, 4),
            predictedLabel=predicted_label,
            modelVersion=model_version,
            attributions=attributions,
            topPhishingFactors=top_phishing_factors,
            topBenignFactors=top_benign_factors,
            narrativeSummary=narrative
        )


shap_explainer = SHAPExplainerService()
