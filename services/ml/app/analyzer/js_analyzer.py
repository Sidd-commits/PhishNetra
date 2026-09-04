"""
PhishNetra - Static JavaScript Heuristic Engine
Module: services.ml.app.analyzer.js_analyzer
Milestone: 3
"""

import re
from typing import Dict, Any, List


class JSHeuristicAnalyzer:
    """
    Lightweight static JavaScript heuristic analyzer detecting obfuscation,
    dynamic code evaluation, and redirection manipulation.
    """

    EVAL_REGEX = re.compile(r"\beval\s*\(", re.IGNORECASE)
    DOC_WRITE_REGEX = re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.IGNORECASE)
    DECODE_REGEX = re.compile(r"\b(?:unescape|decodeURI|decodeURIComponent|atob|String\.fromCharCode)\s*\(", re.IGNORECASE)
    OBFUSCATION_PATTERNS = [
        re.compile(r"_0x[a-f0-9]{4,}", re.IGNORECASE),
        re.compile(r"(?:\\x[0-9a-f]{2}){5,}", re.IGNORECASE),
        re.compile(r"(?:\\u[0-9a-f]{4}){5,}", re.IGNORECASE),
        re.compile(r"\[(?:\s*['\"][a-zA-Z0-9_$]+['\"]\s*,\s*){8,}\]", re.IGNORECASE)  # Array string tables
    ]
    REDIRECT_REGEX = re.compile(r"\b(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*=", re.IGNORECASE)

    @classmethod
    def analyze_scripts(cls, scripts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for script in scripts:
            src = script.get("src", "").strip()
            content = script.get("content", "")
            is_external = bool(src)

            has_eval = bool(cls.EVAL_REGEX.search(content))
            has_doc_write = bool(cls.DOC_WRITE_REGEX.search(content))
            has_decode = bool(cls.DECODE_REGEX.search(content))
            has_redirect = bool(cls.REDIRECT_REGEX.search(content))

            obfuscation_matches = sum(1 for pat in cls.OBFUSCATION_PATTERNS if pat.search(content))
            has_obfuscation = obfuscation_matches > 0

            reasons: List[str] = []
            if has_eval:
                reasons.append("Dynamic code evaluation (eval()) detected")
            if has_doc_write:
                reasons.append("Dynamic DOM writing (document.write) detected")
            if has_decode:
                reasons.append("String decoding routine (atob / fromCharCode) detected")
            if has_obfuscation:
                reasons.append(f"Hex/Array-packed obfuscation signature detected ({obfuscation_matches} patterns)")
            if has_redirect:
                reasons.append("Client-side location redirection manipulation detected")

            if reasons or is_external or content:
                findings.append({
                    "src": src if is_external else None,
                    "isExternal": is_external,
                    "hasObfuscation": has_obfuscation,
                    "hasEval": has_eval,
                    "hasDocumentWrite": has_doc_write,
                    "hasSuspiciousRedirect": has_redirect,
                    "reasons": reasons
                })

        return findings


js_analyzer = JSHeuristicAnalyzer()
