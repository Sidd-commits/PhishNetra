"""
Unit Tests for SHAP Feature Attribution & Explainability
Module: services.ml.tests.test_explainability
Milestone: 7
"""

import pytest
from app.models.explainability import shap_explainer, get_human_description
from app.models.baseline import model_service


def test_shap_explanation_structure():
    url = "http://192.168.1.1/login-account-update.php?token=892348"
    explanation = shap_explainer.explain(url, model_service)

    assert explanation.url == url
    assert 0.0 <= explanation.baseValue <= 1.0
    assert 0.0 <= explanation.predictedProbability <= 1.0
    assert explanation.predictedLabel in (0, 1)
    assert len(explanation.attributions) > 0
    assert isinstance(explanation.narrativeSummary, str)
    assert len(explanation.narrativeSummary) > 10


def test_shap_additivity_and_contributions():
    url = "https://paypal.com.verify-account.top/secure"
    explanation = shap_explainer.explain(url, model_service)

    # Sum of contribution percentages should be approximately 100%
    total_pct = sum(a.contributionPercent for a in explanation.attributions)
    assert 99.0 <= total_pct <= 101.0

    # Ensure directions are valid
    for a in explanation.attributions:
        assert a.direction in ("PHISHING", "BENIGN")
        assert len(a.humanDescription) > 0


def test_human_description_generator():
    desc_phish = get_human_description("has_ip_address", 1, "PHISHING")
    assert "Direct IP address" in desc_phish

    desc_benign = get_human_description("has_https", 1, "BENIGN")
    assert "HTTPS" in desc_benign
