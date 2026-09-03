"""
Unit tests for URL feature extraction and canonicalization
Module: services.ml.tests.test_features
"""

import pytest
from app.features.url_features import (
    URLFeatureExtractor,
    normalize_url,
    calculate_entropy,
    is_ip_address,
    FEATURE_COLUMNS
)


def test_normalize_url():
    assert normalize_url("google.com") == "http://google.com/"
    assert normalize_url("https://google.com:443/search?q=test") == "https://google.com/search?q=test"
    assert normalize_url("http://example.com:80/") == "http://example.com/"


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") == 1
    assert is_ip_address("10.0.0.1:8080") == 1
    assert is_ip_address("google.com") == 0
    assert is_ip_address("paypal.com.attacker.xyz") == 0


def test_calculate_entropy():
    # Low entropy for repetitive strings
    assert calculate_entropy("aaaaaaa") == 0.0
    # Higher entropy for random characters
    assert calculate_entropy("a8!z9Q#1x") > 2.5


def test_feature_extraction_legitimate():
    url = "https://www.google.com/search?q=cybersecurity"
    features = URLFeatureExtractor.extract_features(url)
    
    assert features["has_https"] == 1
    assert features["has_ip_address"] == 0
    assert features["subdomain_count"] <= 1
    assert features["suspicious_keyword_count"] == 0
    assert len(features) == len(FEATURE_COLUMNS)


def test_feature_extraction_phishing():
    url = "http://192.168.1.100/secure-bank-login/update.php?account=verify&token=abc"
    features = URLFeatureExtractor.extract_features(url)
    
    assert features["has_https"] == 0
    assert features["has_ip_address"] == 1
    assert features["suspicious_keyword_count"] >= 3  # secure, bank, login, update, account, verify
    assert features["digit_count"] > 0
    assert features["special_char_count"] > 0


def test_feature_vector_order_and_types():
    url = "https://example.com/test"
    vector = URLFeatureExtractor.extract_vector(url)
    assert len(vector) == len(FEATURE_COLUMNS)
    assert all(isinstance(val, (int, float)) for val in vector)
