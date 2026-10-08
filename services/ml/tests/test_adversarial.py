"""
Unit Tests for Adversarial Evasion Hardening & Robustness
Module: services.ml.tests.test_adversarial
Milestone: 7
"""

import pytest
from app.security.adversarial import adversarial_engine, HOMOGLYPH_MAP


def test_homoglyph_perturbation():
    url = "https://paypal.com/login"
    perturbed = adversarial_engine.apply_homoglyph(url)
    assert perturbed != url
    # Contains at least one homoglyph character
    assert any(h in perturbed for h in HOMOGLYPH_MAP.values())


def test_keyword_stuffing_perturbation():
    url = "https://phishing-site.xyz/auth"
    perturbed = adversarial_engine.apply_keyword_stuffing(url)
    assert "privacy-policy" in perturbed
    assert "help" in perturbed


def test_subdomain_packing_perturbation():
    url = "https://evil.xyz"
    perturbed = adversarial_engine.apply_subdomain_packing(url)
    assert "sso.identity" in perturbed
    assert "evil.xyz" in perturbed


def test_adversarial_evaluation_single_url():
    target = "http://192.168.1.1/update.php"
    results = adversarial_engine.evaluate_url(target)
    assert len(results) == 6
    for r in results:
        assert r.originalUrl == target
        assert 0.0 <= r.originalScore <= 100.0
        assert 0.0 <= r.perturbedScore <= 100.0
        assert isinstance(r.evaded, bool)


def test_adversarial_suite_execution():
    report = adversarial_engine.run_suite()
    assert report.totalTests > 0
    assert 0.0 <= report.evasionRate <= 1.0
    assert 0.0 <= report.overallRobustnessScore <= 100.0
    assert report.hardeningStatus in ("ROBUST", "VULNERABLE", "CRITICAL_DEFICIT")
