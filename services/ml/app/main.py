"""
PhishNetra - Python ML Inference Microservice
Module: services.ml.app.main
Milestone: 1
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.schemas import HealthResponse
from app.api.endpoints import router as api_router
from app.models.baseline import model_service

app = FastAPI(
    title="PhishNetra ML Inference Service",
    description="Real-time URL Feature Extraction and Baseline Machine Learning Classification API for PhishNetra",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attach API routes
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """
    Health check endpoint reporting ML microservice readiness and model status.
    """
    return HealthResponse(
        status="healthy",
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        model_loaded=model_service.is_ready,
        model_version=model_service.version if model_service.is_ready else None
    )


@app.get("/", tags=["Root"])
async def root():
    return {
        "service": "PhishNetra ML Microservice",
        "version": "0.1.0",
        "milestone": "1",
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        log_level=settings.LOG_LEVEL,
        reload=True
    )
