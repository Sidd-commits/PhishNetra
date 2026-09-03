"""
PhishNetra - Baseline ML Model Inference Wrapper
Module: services.ml.app.models.baseline
Milestone: 1
"""

import os
import time
from typing import Optional, Dict, Any, Tuple
import joblib
import pandas as pd
import numpy as np

from app.core.config import settings
from app.core.schemas import URLFeatureVectorModel, PredictionResponse
from app.features.url_features import (
    URLFeatureExtractor,
    FEATURE_COLUMNS,
    normalize_url
)


class BaselineModelService:
    """
    Manages model loading, feature extraction, and real-time inference.
    """

    def __init__(self):
        self.model = None
        self.feature_columns = FEATURE_COLUMNS
        self.version = "v0.1.0-baseline"
        self._load_model()

    def _load_model(self):
        """Loads serialized scikit-learn model artifact if available."""
        if os.path.exists(settings.MODEL_PATH):
            try:
                artifact = joblib.load(settings.MODEL_PATH)
                if isinstance(artifact, dict) and "model" in artifact:
                    self.model = artifact["model"]
                    self.feature_columns = artifact.get("feature_columns", FEATURE_COLUMNS)
                    self.version = artifact.get("version", "v0.1.0-baseline")
                else:
                    self.model = artifact
                print(f"[+] Loaded baseline ML model from: {settings.MODEL_PATH}")
            except Exception as e:
                print(f"[!] Warning: Could not load model from {settings.MODEL_PATH}: {e}")
                self.model = None
        else:
            print(f"[!] Model artifact not found at {settings.MODEL_PATH}. Will initialize upon training.")

    @property
    def is_ready(self) -> bool:
        return self.model is not None

    def predict(self, raw_url: str) -> PredictionResponse:
        """
        Executes feature extraction and model inference for a single URL.
        """
        start_time = time.perf_counter()
        normalized = normalize_url(raw_url)
        raw_features = URLFeatureExtractor.extract_features(normalized)
        feature_model = URLFeatureVectorModel(**raw_features)

        if self.model is not None:
            # Predict using trained RandomForest / scikit-learn model
            feature_df = pd.DataFrame([raw_features])[self.feature_columns]
            probabilities = self.model.predict_proba(feature_df)[0]
            # Probability of class 1 (phishing)
            phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
            predicted_label = int(self.model.predict(feature_df)[0])
        else:
            # Fallback heuristic calculation if artifact not yet generated
            score_acc = 0.0
            if raw_features["has_ip_address"] == 1:
                score_acc += 0.35
            if raw_features["suspicious_keyword_count"] > 0:
                score_acc += min(0.30, raw_features["suspicious_keyword_count"] * 0.15)
            if raw_features["has_https"] == 0:
                score_acc += 0.15
            if raw_features["subdomain_count"] >= 3:
                score_acc += 0.20
            if raw_features["hyphen_count"] >= 2:
                score_acc += 0.15
            if raw_features["entropy"] > 4.5:
                score_acc += 0.15

            phishing_prob = min(1.0, max(0.0, score_acc))
            predicted_label = 1 if phishing_prob >= 0.5 else 0

        # Confidence: measure of distance from ambiguous 0.5 boundary
        confidence = round(float(abs(phishing_prob - 0.5) * 2.0), 4)
        inference_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return PredictionResponse(
            url=raw_url,
            normalized_url=normalized,
            features=feature_model,
            phishing_probability=round(phishing_prob, 4),
            confidence=confidence,
            predicted_label=predicted_label,
            model_version=self.version,
            inference_time_ms=inference_time_ms
        )


# Singleton instance for FastAPI dependency injection
model_service = BaselineModelService()
