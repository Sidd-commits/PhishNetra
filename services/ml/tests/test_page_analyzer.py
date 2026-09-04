"""
PhishNetra - Page Content Analyzer Unit Tests
Module: services.ml.tests.test_page_analyzer
Milestone: 3
"""

import os
import pytest
from app.analyzer.dom_analyzer import dom_analyzer
from app.analyzer.form_analyzer import form_analyzer
from app.analyzer.js_analyzer import js_analyzer
from app.analyzer.brand_analyzer import brand_analyzer
from app.features.content_features import content_feature_extractor
from app.models.content_model import content_risk_model


FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(filename: str) -> str:
    path = os.path.join(FIXTURES_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestPageContentAnalyzer:
    """
    Test suite verifying deterministic HTML fixture analysis.
    """

    def test_normal_page_fixture(self):
        html = load_fixture("normal.html")
        dom_res = dom_analyzer.analyze_html(html, base_url="https://techblog.com")

        assert "Cybersecurity" in dom_res["title"]
        assert dom_res["metrics"]["formsCount"] == 0
        assert dom_res["metrics"]["passwordInputsCount"] == 0

        forms_res = form_analyzer.analyze_forms(dom_res["forms"], base_url="https://techblog.com")
        assert len(forms_res) == 0

        brand_res, kw_res, urgency = brand_analyzer.analyze("https://techblog.com", dom_res["title"], dom_res["visible_text"], forms_res)
        assert len(brand_res) == 0

        features = content_feature_extractor.extract_features(
            dom_result=dom_res,
            forms=forms_res,
            iframes=dom_res["iframes"],
            scripts=dom_res["scripts"],
            script_findings=[],
            brand_findings=brand_res,
            keyword_findings=kw_res,
            urgency_score=urgency,
            redirect_count=0
        )
        risk, prob, conf = content_risk_model.evaluate_content_risk(features)
        assert risk < 20.0
        assert prob < 0.20

    def test_suspicious_login_fixture(self):
        html = load_fixture("suspicious-login.html")
        dom_res = dom_analyzer.analyze_html(html, base_url="http://example-suspicious.com/verify")

        assert dom_res["metrics"]["formsCount"] == 1
        assert dom_res["metrics"]["passwordInputsCount"] >= 1

        forms_res = form_analyzer.analyze_forms(dom_res["forms"], base_url="http://example-suspicious.com/verify")
        assert len(forms_res) == 1
        assert forms_res[0]["hasPasswordField"] is True
        assert forms_res[0]["isCrossOrigin"] is True or forms_res[0]["isIpAction"] is True
        assert forms_res[0]["hasCreditCardField"] is True

        brand_res, kw_res, urgency = brand_analyzer.analyze(
            "http://example-suspicious.com/verify",
            dom_res["title"],
            dom_res["visible_text"],
            forms_res
        )
        assert urgency > 0.30

        features = content_feature_extractor.extract_features(
            dom_result=dom_res,
            forms=forms_res,
            iframes=dom_res["iframes"],
            scripts=dom_res["scripts"],
            script_findings=[],
            brand_findings=brand_res,
            keyword_findings=kw_res,
            urgency_score=urgency,
            redirect_count=0
        )
        assert features["has_login_form"] == 1
        assert features["external_form_actions"] >= 1

        risk, prob, conf = content_risk_model.evaluate_content_risk(features)
        assert risk >= 50.0  # High content threat risk

    def test_brand_mismatch_fixture(self):
        html = load_fixture("brand-mismatch.html")
        unrelated_url = "http://secure-account-verification-portal99.xyz/login"
        dom_res = dom_analyzer.analyze_html(html, base_url=unrelated_url)

        forms_res = form_analyzer.analyze_forms(dom_res["forms"], base_url=unrelated_url)
        brand_res, kw_res, urgency = brand_analyzer.analyze(
            unrelated_url,
            dom_res["title"],
            dom_res["visible_text"],
            forms_res
        )

        assert len(brand_res) >= 1
        ms_brand = next((b for b in brand_res if b["claimedBrand"] == "Microsoft"), None)
        assert ms_brand is not None
        assert ms_brand["isMismatch"] is True
        assert "portal99.xyz" in ms_brand["actualDomain"]

        features = content_feature_extractor.extract_features(
            dom_result=dom_res,
            forms=forms_res,
            iframes=dom_res["iframes"],
            scripts=dom_res["scripts"],
            script_findings=[],
            brand_findings=brand_res,
            keyword_findings=kw_res,
            urgency_score=urgency,
            redirect_count=0
        )
        assert features["brand_domain_mismatch"] == 1

        risk, prob, conf = content_risk_model.evaluate_content_risk(features)
        assert risk >= 60.0

    def test_obfuscated_javascript_fixture(self):
        html = load_fixture("obfuscated-js.html")
        dom_res = dom_analyzer.analyze_html(html, base_url="http://example.com")
        script_findings = js_analyzer.analyze_scripts(dom_res["scripts"])

        assert len(script_findings) >= 1
        assert script_findings[0]["hasEval"] is True
        assert script_findings[0]["hasObfuscation"] is True
        assert script_findings[0]["hasSuspiciousRedirect"] is True

    def test_iframe_heavy_fixture(self):
        html = load_fixture("iframe-heavy.html")
        dom_res = dom_analyzer.analyze_html(html, base_url="http://example.com")
        assert dom_res["metrics"]["iframesCount"] == 3
        hidden_iframes = [ifr for ifr in dom_res["iframes"] if ifr.get("hidden")]
        assert len(hidden_iframes) >= 1

    def test_malformed_html_fixture(self):
        html = load_fixture("malformed.html")
        dom_res = dom_analyzer.analyze_html(html, base_url="http://example.com")
        assert dom_res["metrics"]["nodeCount"] > 0
        assert dom_res["metrics"]["formsCount"] >= 1
        assert dom_res["metrics"]["suspiciousLinksCount"] >= 1
