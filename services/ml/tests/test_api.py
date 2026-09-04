"""
API Endpoint tests for FastAPI ML & Page Analyzer Microservice
Module: services.ml.tests.test_api
Milestone: 3
"""

import pytest
from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert data["model_version"] is not None


def test_predict_endpoint_legitimate():
    response = client.post(
        "/api/v1/predict",
        json={"url": "https://www.wikipedia.org/wiki/Phishing"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "features" in data
    assert "phishing_probability" in data
    assert "confidence" in data
    assert data["predicted_label"] in (0, 1)
    assert data["phishing_probability"] < 0.5


def test_predict_endpoint_phishing():
    response = client.post(
        "/api/v1/predict",
        json={"url": "http://192.168.1.50/paypal-login-verify-account/signin.php"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["phishing_probability"] >= 0.5
    assert data["predicted_label"] == 1


def test_features_endpoint():
    response = client.post(
        "/api/v1/features",
        json={"url": "https://github.com/torvalds/linux"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["features"]["has_https"] == 1
    assert data["features"]["has_ip_address"] == 0


def test_ssrf_validation_endpoint():
    # Prohibited target
    res_blocked = client.post(
        "/api/v1/validate-ssrf",
        json={"url": "http://169.254.169.254/latest/meta-data/"}
    )
    assert res_blocked.status_code == 200
    data_blocked = res_blocked.json()
    assert data_blocked["is_safe"] is False
    assert "prohibited" in data_blocked["block_reason"].lower()

    # Safe target
    res_safe = client.post(
        "/api/v1/validate-ssrf",
        json={"url": "https://example.com"}
    )
    assert res_safe.status_code == 200
    data_safe = res_safe.json()
    assert data_safe["is_safe"] is True
    assert data_safe["block_reason"] is None


def test_analyze_page_endpoint_ssrf_blocked():
    response = client.post(
        "/api/v1/analyze-page",
        json={"url": "http://127.0.0.1:8080/admin", "timeout_ms": 5000}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "BLOCKED"
    assert "prohibited" in data["blockReason"].lower() or "loopback" in data["blockReason"].lower()
    assert data["contentRiskScore"] >= 80.0
