"""
PhishNetra - Content Feature Extraction Engine
Module: services.ml.app.features.content_features
Milestone: 3
"""

from typing import Dict, Any, List


class ContentFeatureExtractor:
    """
    Constructs normalized 20-dimensional content feature vectors from extracted page artifacts.
    """

    @classmethod
    def extract_features(
        cls,
        dom_result: Dict[str, Any],
        forms: List[Dict[str, Any]],
        iframes: List[Dict[str, Any]],
        scripts: List[Dict[str, Any]],
        script_findings: List[Dict[str, Any]],
        brand_findings: List[Dict[str, Any]],
        keyword_findings: List[Dict[str, Any]],
        urgency_score: float,
        redirect_count: int
    ) -> Dict[str, Any]:
        metrics = dom_result.get("metrics", {})
        visible_text = dom_result.get("visible_text", "")

        has_login_form = 1 if any(f.get("hasPasswordField") for f in forms) else 0
        external_form_actions = sum(1 for f in forms if f.get("isCrossOrigin") or f.get("isIpAction"))

        hidden_iframes = sum(1 for ifr in iframes if ifr.get("isHidden") or ifr.get("hidden"))
        external_iframes = sum(1 for ifr in iframes if ifr.get("isCrossOrigin"))

        obfuscated_scripts = sum(1 for sf in script_findings if sf.get("hasObfuscation") or sf.get("hasEval"))

        suspicious_keywords_count = sum(kf.get("count", 0) for kf in keyword_findings)
        brand_references_count = len(brand_findings)
        has_brand_mismatch = 1 if any(bf.get("isMismatch") for bf in brand_findings) else 0

        external_domains_count = len(dom_result.get("external_domains", []))

        return {
            "forms_count": metrics.get("formsCount", len(forms)),
            "password_inputs": metrics.get("passwordInputsCount", 0),
            "text_inputs": metrics.get("inputsCount", 0),
            "hidden_inputs": metrics.get("hiddenInputsCount", 0),
            "has_login_form": has_login_form,
            "external_form_actions": external_form_actions,
            "iframe_count": metrics.get("iframesCount", len(iframes)),
            "hidden_iframe_count": hidden_iframes,
            "external_iframe_count": external_iframes,
            "script_count": metrics.get("scriptsCount", len(scripts)),
            "external_script_count": metrics.get("externalScriptsCount", 0),
            "obfuscated_script_count": obfuscated_scripts,
            "external_domain_count": external_domains_count,
            "suspicious_keyword_count": suspicious_keywords_count,
            "urgency_score": round(urgency_score, 2),
            "brand_reference_count": brand_references_count,
            "brand_domain_mismatch": has_brand_mismatch,
            "redirect_count": redirect_count,
            "suspicious_link_count": metrics.get("suspiciousLinksCount", 0),
            "page_text_length": len(visible_text)
        }


content_feature_extractor = ContentFeatureExtractor()
