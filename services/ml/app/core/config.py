"""
PhishNetra - ML Service Configuration
Module: services.ml.app.core.config
Milestone: 1
"""

import os
from pathlib import Path
from pydantic import BaseModel

ML_ROOT = Path(__file__).resolve().parent.parent.parent


class Settings(BaseModel):
    PROJECT_NAME: str = "PhishNetra ML Inference Service"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "info")
    
    ARTIFACTS_DIR: Path = ML_ROOT / "artifacts"
    MODEL_PATH: Path = ML_ROOT / "artifacts" / "baseline_model.joblib"
    METRICS_PATH: Path = ML_ROOT / "artifacts" / "metrics.json"


settings = Settings()
