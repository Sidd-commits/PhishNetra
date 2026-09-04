"""
PhishNetra - ML & Isolated Page Analyzer API Endpoints
Module: services.ml.app.api.endpoints
Milestone: 3
"""

from fastapi import APIRouter, HTTPException, status
from app.core.schemas import (
    PredictionRequest,
    PredictionResponse,
    FeatureExtractionRequest,
    FeatureExtractionResponse,
    URLFeatureVectorModel,
    PageAnalysisRequest,
    PageAnalysisResponse,
    SSRFValidationRequest,
    SSRFValidationResponse,
    FormFindingModel,
    IFrameFindingModel,
    ScriptFindingModel,
    BrandFindingModel,
    KeywordFindingModel,
    DOMMetricsModel,
    NetworkMetricsModel,
    ScreenshotMetadataModel,
    ContentFeatureVectorModel,
    RedirectHopModel
)
from app.core.config import settings
from app.models.baseline import model_service
from app.features.url_features import URLFeatureExtractor, normalize_url
from app.security.ssrf import ssrf_validator
from app.analyzer.page_fetcher import page_fetcher
from app.analyzer.dom_analyzer import dom_analyzer
from app.analyzer.form_analyzer import form_analyzer
from app.analyzer.js_analyzer import js_analyzer
from app.analyzer.brand_analyzer import brand_analyzer
from app.features.content_features import content_feature_extractor
from app.models.content_model import content_risk_model

router = APIRouter()


@router.post(
    "/predict",
    response_model=PredictionResponse,
    summary="Predict Phishing Probability for URL (Lexical ML Model)",
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


@router.post(
    "/analyze-page",
    response_model=PageAnalysisResponse,
    summary="Secure Isolated Page Content & DOM Analysis",
    description="Fetches webpage in an isolated sandbox, extracts DOM, form, script, brand, and social engineering indicators with strict SSRF defense."
)
@router.post("/page-analyze", response_model=PageAnalysisResponse, include_in_schema=False)
async def analyze_page_content(payload: PageAnalysisRequest):
    if not payload.url or not payload.url.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="URL parameter cannot be empty"
        )

    # 1. Isolated Page Acquisition
    fetch_result = await page_fetcher.fetch_page(
        target_url=payload.url,
        capture_screenshot=payload.capture_screenshot,
        timeout_ms=payload.timeout_ms
    )

    fetch_status = fetch_result.get("status", "FAILED")
    requested_url = fetch_result.get("requestedUrl", payload.url)
    final_url = fetch_result.get("finalUrl", requested_url)
    redirect_chain = [RedirectHopModel(**hop) for hop in fetch_result.get("redirectChain", [])]
    network_metrics_data = fetch_result.get("networkMetrics")
    network_metrics = NetworkMetricsModel(**network_metrics_data) if network_metrics_data else None
    screenshot_data = fetch_result.get("screenshot")
    screenshot = ScreenshotMetadataModel(**screenshot_data) if screenshot_data else None

    # Handle non-completed acquisition gracefully (e.g. SSRF blocked, timeout, unreachable)
    if fetch_status != "COMPLETED":
        return PageAnalysisResponse(
            status=fetch_status,
            requestedUrl=requested_url,
            finalUrl=final_url,
            pageTitle=None,
            redirectCount=fetch_result.get("redirectCount", 0),
            redirectChain=redirect_chain,
            domMetrics=None,
            forms=[],
            iframes=[],
            scripts=[],
            keywords=[],
            brandFindings=[],
            networkMetrics=network_metrics,
            contentFeatures=None,
            screenshot=None,
            urgencyScore=0.0,
            contentRiskScore=90.0 if fetch_status == "BLOCKED" else 0.0,
            phishingProbability=0.90 if fetch_status == "BLOCKED" else 0.0,
            confidence=0.95 if fetch_status == "BLOCKED" else 0.50,
            error=fetch_result.get("error"),
            blockReason=fetch_result.get("blockReason"),
            acquisitionTimeMs=fetch_result.get("acquisitionTimeMs", 0.0)
        )

    # 2. DOM & Structural Extraction
    html_content = fetch_result.get("html", "")
    dom_result = dom_analyzer.analyze_html(html_content, base_url=final_url)
    page_title = dom_result.get("title") or fetch_result.get("pageTitle", "")

    # 3. Form & Sensitive Input Analysis
    form_findings_raw = form_analyzer.analyze_forms(dom_result.get("forms", []), base_url=final_url)
    form_findings = [FormFindingModel(**f) for f in form_findings_raw]

    # 4. JavaScript Static Heuristics
    script_findings_raw = js_analyzer.analyze_scripts(dom_result.get("scripts", []))
    script_findings = [ScriptFindingModel(**s) for s in script_findings_raw]

    # 5. IFrame Findings
    iframe_findings = [
        IFrameFindingModel(
            src=ifr.get("src", ""),
            isCrossOrigin=bool(ifr.get("src") and final_url not in ifr.get("src", "")),
            isHidden=bool(ifr.get("hidden")),
            width=ifr.get("width", ""),
            height=ifr.get("height", "")
        )
        for ifr in dom_result.get("iframes", [])
    ]

    # 6. Brand Consistency & Keyword Scorer
    brand_findings_raw, keyword_findings_raw, urgency_score = brand_analyzer.analyze(
        base_url=final_url,
        title=page_title,
        visible_text=dom_result.get("visible_text", ""),
        forms=form_findings_raw
    )
    brand_findings = [BrandFindingModel(**b) for b in brand_findings_raw]
    keyword_findings = [KeywordFindingModel(**k) for k in keyword_findings_raw]

    # 7. Content Feature Vector Construction
    features_dict = content_feature_extractor.extract_features(
        dom_result=dom_result,
        forms=form_findings_raw,
        iframes=dom_result.get("iframes", []),
        scripts=dom_result.get("scripts", []),
        script_findings=script_findings_raw,
        brand_findings=brand_findings_raw,
        keyword_findings=keyword_findings_raw,
        urgency_score=urgency_score,
        redirect_count=fetch_result.get("redirectCount", 0)
    )
    content_features = ContentFeatureVectorModel(**features_dict)

    # 8. Content Risk & Phishing Probability Synthesis
    content_risk_score, phishing_prob, confidence = content_risk_model.evaluate_content_risk(features_dict)

    return PageAnalysisResponse(
        status="COMPLETED",
        requestedUrl=requested_url,
        finalUrl=final_url,
        pageTitle=page_title,
        redirectCount=fetch_result.get("redirectCount", 0),
        redirectChain=redirect_chain,
        domMetrics=DOMMetricsModel(**dom_result.get("metrics", {})),
        forms=form_findings,
        iframes=iframe_findings,
        scripts=script_findings,
        keywords=keyword_findings,
        brandFindings=brand_findings,
        networkMetrics=network_metrics,
        contentFeatures=content_features,
        screenshot=screenshot,
        urgencyScore=urgency_score,
        contentRiskScore=content_risk_score,
        phishingProbability=phishing_prob,
        confidence=confidence,
        error=None,
        blockReason=None,
        acquisitionTimeMs=fetch_result.get("acquisitionTimeMs", 0.0)
    )


@router.post(
    "/validate-ssrf",
    response_model=SSRFValidationResponse,
    summary="Pre-flight SSRF & DNS Rebinding Validator",
    description="Tests URL, host, and resolved IP against prohibited RFC1918, link-local, loopback, and metadata ranges."
)
async def validate_ssrf(payload: SSRFValidationRequest):
    is_safe, block_reason, hostname = ssrf_validator.validate_url(payload.url)
    if not is_safe:
        return SSRFValidationResponse(
            url=payload.url,
            is_safe=False,
            block_reason=block_reason,
            hostname=hostname,
            resolved_ips=[]
        )

    dns_safe, dns_reason, resolved_ips = ssrf_validator.resolve_and_validate(hostname)
    return SSRFValidationResponse(
        url=payload.url,
        is_safe=dns_safe,
        block_reason=dns_reason,
        hostname=hostname,
        resolved_ips=resolved_ips
    )
