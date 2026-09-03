"""
PhishNetra - Pydantic Schemas for ML Microservice
Module: services.ml.app.core.schemas
Milestone: 1
"""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class URLFeatureVectorModel(BaseModel):
    url_length: int = Field(..., description="Total length of normalized URL")
    hostname_length: int = Field(..., description="Length of hostname")
    path_length: int = Field(..., description="Length of path")
    query_length: int = Field(..., description="Length of query string")
    subdomain_count: int = Field(..., description="Number of subdomains")
    has_ip_address: int = Field(..., description="1 if IP is used as hostname else 0")
    has_https: int = Field(..., description="1 if scheme is https else 0")
    special_char_count: int = Field(..., description="Count of special characters")
    digit_count: int = Field(..., description="Count of digits in URL")
    hyphen_count: int = Field(..., description="Count of hyphens in hostname")
    at_symbol_count: int = Field(..., description="Count of @ symbols")
    double_slash_in_path: int = Field(..., description="1 if double slash in path else 0")
    encoded_char_count: int = Field(..., description="Count of % encoded sequences")
    suspicious_keyword_count: int = Field(..., description="Count of matching phishing keywords")
    entropy: float = Field(..., description="Shannon entropy of URL string")
    tld_in_subdomain: int = Field(..., description="1 if TLD detected in subdomain else 0")
    port_in_url: int = Field(..., description="1 if non-standard port specified else 0")
    tld_length: int = Field(..., description="Length of top-level domain")


class PredictionRequest(BaseModel):
    url: str = Field(..., min_length=1, description="Raw or normalized URL to analyze")


class PredictionResponse(BaseModel):
    url: str
    normalized_url: str
    features: URLFeatureVectorModel
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    confidence: float = Field(..., ge=0.0, le=1.0)
    predicted_label: int = Field(..., description="0 for Legitimate, 1 for Phishing")
    model_version: str
    inference_time_ms: float


class FeatureExtractionRequest(BaseModel):
    url: str = Field(..., min_length=1)


class FeatureExtractionResponse(BaseModel):
    url: str
    normalized_url: str
    features: URLFeatureVectorModel


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    model_loaded: bool
    model_version: Optional[str] = None
