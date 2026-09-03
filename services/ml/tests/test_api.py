"""
API Endpoint tests for FastAPI ML Microservice
Module: services.ml.tests.test_api
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
