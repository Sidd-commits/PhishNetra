"""
PhishNetra - ML Service API Endpoints
Module: services.ml.app.api.endpoints
Milestone: 1
"""

from fastapi import APIRouter, HTTPException, status
from app.core.schemas import (
    PredictionRequest,
    PredictionResponse,
    FeatureExtractionRequest,
    FeatureExtractionResponse,
    URLFeatureVectorModel,
    HealthResponse
)
from app.core.config import settings
from app.models.baseline import model_service
from app.features.url_features import URLFeatureExtractor, normalize_url

router = APIRouter()


@router.post(
    "/predict",
    response_model=PredictionResponse,
    summary="Predict Phishing Probability for URL",
    description="Extracts deterministic URL features and passes the vector through the baseline classification model."
)
async def predict_url(payload: PredictionRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL parameter cannot be empty"
        )
    try:
        result = model_service.predict(payload.url)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference error: {str(e)}"
        )


@router.post(
    "/features",
    response_model=FeatureExtractionResponse,
    summary="Extract Deterministic URL Features",
    description="Returns the raw extracted 18+ URL feature dictionary without model evaluation."
)
async def extract_features_only(payload: FeatureExtractionRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL parameter cannot be empty"
        )
    try:
        normalized = normalize_url(payload.url)
        raw_features = URLFeatureExtractor.extract_features(normalized)
        return FeatureExtractionResponse(
            url=payload.url,
            normalized_url=normalized,
            features=URLFeatureVectorModel(**raw_features)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Feature extraction error: {str(e)}"
        )
