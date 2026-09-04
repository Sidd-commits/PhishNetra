"""
PhishNetra - Content Risk Assessment Model
Module: services.ml.app.models.content_model
Milestone: 3
"""

from typing import Dict, Any, Tuple


class ContentRiskModel:
    """
    Synthesizes extracted DOM, form, brand, script, and linguistic signals into
    a normalized content risk score and confidence rating.
    """

    @classmethod
    def evaluate_content_risk(cls, features: Dict[str, Any]) -> Tuple[float, float, float]:
        """
        Returns: (content_risk_score: 0-100, phishing_probability: 0.0-1.0, confidence: 0.0-1.0)
        """
        score = 0.0

        # 1. Brand Impersonation Signals (High Weight)
        if features.get("brand_domain_mismatch", 0) == 1:
            score += 55.0  # Dominant phishing indicator

        # 2. Form & Credential Theft Signals
        if features.get("has_login_form", 0) == 1:
            score += 15.0
            if features.get("external_form_actions", 0) > 0:
                score += 35.0  # Credentials submitted to 3rd party domain

        if features.get("password_inputs", 0) >= 2:
            score += 10.0

        # 3. Hidden & Cross-Origin Iframes
        if features.get("hidden_iframe_count", 0) > 0:
            score += 20.0
        elif features.get("external_iframe_count", 0) > 2:
            score += 10.0

        # 4. JavaScript Obfuscation & Evasion
        if features.get("obfuscated_script_count", 0) > 0:
            score += min(25.0, features["obfuscated_script_count"] * 12.0)

        # 5. Social Engineering & Urgency Signals
        urgency = features.get("urgency_score", 0.0)
        if urgency > 0.5:
            score += 20.0
        elif urgency > 0.2:
            score += 10.0

        if features.get("suspicious_keyword_count", 0) >= 4:
            score += min(15.0, features["suspicious_keyword_count"] * 2.5)

        # 6. Redirect Manipulation
        redirects = features.get("redirect_count", 0)
        if redirects >= 2:
            score += min(20.0, redirects * 6.0)

        final_score = min(100.0, max(0.0, score))
        phishing_prob = round(final_score / 100.0, 3)

        # Confidence is derived from signal density and completeness
        signal_count = (
            (1 if features.get("has_login_form") else 0) +
            (1 if features.get("brand_reference_count", 0) > 0 else 0) +
            (1 if features.get("forms_count", 0) > 0 else 0) +
            (1 if features.get("page_text_length", 0) > 100 else 0) +
            (1 if features.get("script_count", 0) > 0 else 0)
        )
        confidence = min(0.95, max(0.30, 0.40 + (signal_count * 0.11)))

        return round(final_score, 1), phishing_prob, round(confidence, 2)


content_risk_model = ContentRiskModel()
