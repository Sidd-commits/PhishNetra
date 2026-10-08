"""
PhishNetra - Pydantic Schemas for ML & Page Analyzer Microservice
Module: services.ml.app.core.schemas
Milestone: 3
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


class ContentFeatureVectorModel(BaseModel):
    forms_count: int = Field(0, description="Total forms detected")
    password_inputs: int = Field(0, description="Count of password fields")
    text_inputs: int = Field(0, description="Count of input fields")
    hidden_inputs: int = Field(0, description="Count of hidden input fields")
    has_login_form: int = Field(0, description="1 if login form detected else 0")
    external_form_actions: int = Field(0, description="Count of cross-origin or IP form submissions")
    iframe_count: int = Field(0, description="Count of iframes")
    hidden_iframe_count: int = Field(0, description="Count of hidden/zero-dimension iframes")
    external_iframe_count: int = Field(0, description="Count of third-party iframes")
    script_count: int = Field(0, description="Count of total script tags")
    external_script_count: int = Field(0, description="Count of external script dependencies")
    obfuscated_script_count: int = Field(0, description="Count of scripts with obfuscation signatures")
    external_domain_count: int = Field(0, description="Number of unique third-party domains referenced")
    suspicious_keyword_count: int = Field(0, description="Count of phishing keywords matched")
    urgency_score: float = Field(0.0, description="Social engineering urgency score from 0.0 to 1.0")
    brand_reference_count: int = Field(0, description="Number of known brands referenced")
    brand_domain_mismatch: int = Field(0, description="1 if brand claimed on unrelated domain else 0")
    redirect_count: int = Field(0, description="Number of redirect hops")
    suspicious_link_count: int = Field(0, description="Count of javascript:/data:/mailto: links")
    page_text_length: int = Field(0, description="Character count of visible page body text")


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


class RedirectHopModel(BaseModel):
    url: str
    status: Optional[int] = None
    ip: Optional[str] = None
    headers: Optional[Dict[str, str]] = None


class FormFindingModel(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = ""
    action: str
    actionResolved: str
    method: str = "GET"
    target: Optional[str] = ""
    isCrossOrigin: bool = False
    isIpAction: bool = False
    hasPasswordField: bool = False
    hasEmailField: bool = False
    hasCreditCardField: bool = False
    hasOtpField: bool = False
    passwordFieldCount: int = 0
    inputCount: int = 0
    description: Optional[str] = None


class IFrameFindingModel(BaseModel):
    src: str
    srcResolved: Optional[str] = None
    isCrossOrigin: bool = False
    isHidden: bool = False
    width: Optional[str] = ""
    height: Optional[str] = ""


class ScriptFindingModel(BaseModel):
    src: Optional[str] = None
    isExternal: bool = False
    hasObfuscation: bool = False
    hasEval: bool = False
    hasDocumentWrite: bool = False
    hasSuspiciousRedirect: bool = False
    reasons: List[str] = []


class BrandFindingModel(BaseModel):
    claimedBrand: str
    authenticDomain: str
    actualDomain: str
    isMismatch: bool = False
    confidence: float = 1.0
    matchSources: List[str] = []
    description: Optional[str] = None


class KeywordFindingModel(BaseModel):
    category: str
    count: int
    matchedTerms: List[str] = []


class DOMMetricsModel(BaseModel):
    nodeCount: int = 0
    depth: int = 0
    formsCount: int = 0
    inputsCount: int = 0
    passwordInputsCount: int = 0
    hiddenInputsCount: int = 0
    iframesCount: int = 0
    scriptsCount: int = 0
    externalScriptsCount: int = 0
    linksCount: int = 0
    externalLinksCount: int = 0
    suspiciousLinksCount: int = 0


class NetworkMetricsModel(BaseModel):
    totalRequests: int = 0
    uniqueDomains: List[str] = []
    thirdPartyDomains: List[str] = []
    scriptsLoaded: int = 0
    iframesLoaded: int = 0
    externalFormActions: int = 0
    blockedRequestsCount: int = 0


class ScreenshotMetadataModel(BaseModel):
    available: bool = False
    width: int = 1280
    height: int = 800
    mimeType: Optional[str] = None
    base64Preview: Optional[str] = None


class PageAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, description="Target URL to inspect")
    timeout_ms: int = Field(10000, description="Navigation timeout in milliseconds")
    capture_screenshot: bool = Field(False, description="Whether to capture an ephemeral screenshot thumbnail")


class PageAnalysisResponse(BaseModel):
    status: str = Field(..., description="COMPLETED, BLOCKED, TIMEOUT, FAILED, or PARTIAL")
    requestedUrl: str
    finalUrl: Optional[str] = None
    pageTitle: Optional[str] = None
    redirectCount: int = 0
    redirectChain: List[RedirectHopModel] = []
    domMetrics: Optional[DOMMetricsModel] = None
    forms: List[FormFindingModel] = []
    iframes: List[IFrameFindingModel] = []
    scripts: List[ScriptFindingModel] = []
    keywords: List[KeywordFindingModel] = []
    brandFindings: List[BrandFindingModel] = []
    networkMetrics: Optional[NetworkMetricsModel] = None
    contentFeatures: Optional[ContentFeatureVectorModel] = None
    screenshot: Optional[ScreenshotMetadataModel] = None
    urgencyScore: float = 0.0
    contentRiskScore: float = 0.0
    phishingProbability: float = 0.0
    confidence: float = 1.0
    error: Optional[str] = None
    blockReason: Optional[str] = None
    acquisitionTimeMs: float = 0.0


class SSRFValidationRequest(BaseModel):
    url: str = Field(..., min_length=1)


class SSRFValidationResponse(BaseModel):
    url: str
    is_safe: bool
    block_reason: Optional[str] = None
    hostname: Optional[str] = None
    resolved_ips: List[str] = []


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    model_loaded: bool
    model_version: Optional[str] = None
    playwright_ready: bool = True


# ============================================================================
# Milestone 7: MLOps, SHAP Explainability, Drift & Adversarial Schemas
# ============================================================================

class SHAPFeatureAttributionModel(BaseModel):
    featureName: str
    featureValue: Any
    shapValue: float
    direction: str = Field(..., description="PHISHING or BENIGN")
    contributionPercent: float = Field(..., ge=0.0, le=100.0)
    humanDescription: str


class SHAPExplanationResponse(BaseModel):
    url: str
    baseValue: float
    predictedProbability: float
    predictedLabel: int
    modelVersion: str
    attributions: List[SHAPFeatureAttributionModel]
    topPhishingFactors: List[str]
    topBenignFactors: List[str]
    narrativeSummary: str


class ModelMetadataModel(BaseModel):
    version: str
    algorithm: str
    trainedAt: str
    active: bool
    datasetSamples: int
    accuracy: float
    precision: float
    recall: float
    f1Score: float
    rocAuc: float
    artifactPath: Optional[str] = None
    featureCount: Optional[int] = 18


class ModelRegistryOverviewResponse(BaseModel):
    activeModel: Optional[ModelMetadataModel] = None
    registeredModels: List[ModelMetadataModel]
    totalModels: int


class ModelActivationRequest(BaseModel):
    version: str = Field(..., min_length=1)


class ModelActivationResponse(BaseModel):
    success: bool
    message: str
    activeModel: ModelMetadataModel


class DriftFeatureMetricModel(BaseModel):
    featureName: str
    psiScore: float
    ksStatistic: float
    pValue: float
    isDrifted: bool
    status: str = Field(..., description="STABLE, MODERATE, or DRIFTED")


class DriftReportResponse(BaseModel):
    generatedAt: str
    overallDriftStatus: str = Field(..., description="STABLE, MODERATE, or CRITICAL")
    baselineSamples: int
    liveSamples: int
    features: List[DriftFeatureMetricModel]
    recommendation: str


class DriftEvaluationRequest(BaseModel):
    live_urls: Optional[List[str]] = None
    custom_samples_count: Optional[int] = 50


class RetrainRequest(BaseModel):
    dataset_path: Optional[str] = None
    augmented_samples: Optional[List[Dict[str, Any]]] = None
    algorithm: Optional[str] = "RandomForest"
    auto_activate_threshold: Optional[float] = 0.90
    version_tag: Optional[str] = None


class RetrainResponse(BaseModel):
    success: bool
    message: str
    newModel: ModelMetadataModel
    previousModelVersion: Optional[str] = None
    activated: bool


class AdversarialTestRequest(BaseModel):
    url: Optional[str] = None
    attack_types: Optional[List[str]] = None
    custom_urls: Optional[List[str]] = None


class AdversarialAttackResultModel(BaseModel):
    attackType: str
    originalUrl: str
    perturbedUrl: str
    originalScore: float
    perturbedScore: float
    evaded: bool
    scoreDiff: float


class AdversarialEvaluationResponse(BaseModel):
    testedAt: str
    totalTests: int
    evasionRate: float
    overallRobustnessScore: float
    results: List[AdversarialAttackResultModel]
    hardeningStatus: str

