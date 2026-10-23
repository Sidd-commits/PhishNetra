"""
PhishNetra - Machine Learning & Detection Optimization Regression Tests
Module: services.ml.tests.test_detection_optimization
"""

import pytest
from app.features.url_features import URLFeatureExtractor, extract_domain_parts
from app.models.baseline import BaselineModelService
from app.analyzer.brand_analyzer import BrandConsistencyAnalyzer
from app.analyzer.form_analyzer import FormAnalyzer
from app.models.content_model import ContentRiskModel


@pytest.fixture
def model_service():
    return BaselineModelService()


def test_url_feature_extractor_gemini_sso():
    url = "https://accounts.google.com/signin?continue=https://gemini.google.com&Email=user@example.com"
    feats = URLFeatureExtractor.extract_features(url)

    # RFC 3986 check: email in query param must NOT trigger userinfo @
    assert feats["at_symbol_count"] == 0
    assert feats["has_ip_address"] == 0
    assert feats["has_https"] == 1
    assert feats["subdomain_count"] == 1


def test_extract_domain_parts_multipart_cctld():
    _, reg, tld, sub = extract_domain_parts("news.bbc.co.uk")
    assert reg == "bbc.co.uk"
    assert tld == "co.uk"
    assert sub == "news"

    _, reg2, tld2, sub2 = extract_domain_parts("maps.google.co.in")
    assert reg2 == "google.co.in"
    assert tld2 == "co.in"
    assert sub2 == "maps"


def test_model_predict_gemini_benign(model_service):
    res_gemini = model_service.predict("https://gemini.google.com")
    assert res_gemini.predicted_label == 0
    assert res_gemini.phishing_probability < 0.10

    res_sso = model_service.predict("https://accounts.google.com/signin?continue=https://gemini.google.com&Email=user@example.com")
    assert res_sso.predicted_label == 0
    assert res_sso.phishing_probability < 0.15


def test_model_predict_phishing_attacks(model_service):
    res_homoglyph = model_service.predict("http://xn--ggle-55da.com/login.html")
    assert res_homoglyph.predicted_label == 1
    assert res_homoglyph.phishing_probability > 0.85

    res_raw_ip = model_service.predict("http://192.168.1.50/secure-bank-login/update.php?account=verify")
    assert res_raw_ip.predicted_label == 1
    assert res_raw_ip.phishing_probability > 0.85

    res_combo = model_service.predict("http://paypal.com.account-update.xyz/login")
    assert res_combo.predicted_label == 1
    assert res_combo.phishing_probability > 0.85


def test_brand_analyzer_gemini_authentic():
    brand_findings, _, _ = BrandConsistencyAnalyzer.analyze(
        base_url="https://gemini.google.com/app",
        title="Google Gemini - Chat with Generative AI",
        visible_text="Welcome to Gemini by Google. Sign in with your Google account to get started.",
        forms=[]
    )
    # Authentic Google domain; must not have any brand mismatch
    assert len(brand_findings) > 0
    assert not any(b["isMismatch"] for b in brand_findings)


def test_brand_analyzer_multipart_cctld_authentic():
    brand_findings, _, _ = BrandConsistencyAnalyzer.analyze(
        base_url="https://google.co.uk/search?q=test",
        title="Google Search UK",
        visible_text="Google UK Search results and Google account services.",
        forms=[]
    )
    assert len(brand_findings) > 0
    assert not any(b["isMismatch"] for b in brand_findings)


def test_brand_analyzer_phishing_mismatch():
    brand_findings, _, _ = BrandConsistencyAnalyzer.analyze(
        base_url="http://google-account-verify.xyz/login",
        title="Google Account Security Verification",
        visible_text="Sign in to your Google Account. Enter your Google password.",
        forms=[]
    )
    assert len(brand_findings) > 0
    assert any(b["isMismatch"] for b in brand_findings)


def test_form_analyzer_sso_not_flagged_as_theft():
    forms = [
        {
            "id": "sso_form",
            "action": "https://accounts.google.com/signin/v2/challenge",
            "method": "POST",
            "inputs": [
                {"name": "Email", "type": "text"},
                {"name": "Passwd", "type": "password"}
            ]
        }
    ]
    findings = FormAnalyzer.analyze_forms(forms, "https://developer.example.com/login")
    assert len(findings) == 1
    # accounts.google.com is an authentic federated SSO provider; must not be flagged as external credential theft
    assert findings[0]["isCrossOrigin"] is False


def test_content_risk_model_safe_page_with_helper_iframe():
    features = {
        "brand_domain_mismatch": 0,
        "has_login_form": 0,
        "external_form_actions": 0,
        "password_inputs": 0,
        "hidden_iframe_count": 1,
        "external_iframe_count": 0,
        "obfuscated_script_count": 0,
        "urgency_score": 0.0,
        "suspicious_keyword_count": 0,
        "redirect_count": 0,
        "page_text_length": 500,
        "script_count": 4
    }
    score, prob, conf = ContentRiskModel.evaluate_content_risk(features)
    # Helper iframe on clean page must not receive aggressive 20+ score
    assert score <= 10.0
    assert prob < 0.15
