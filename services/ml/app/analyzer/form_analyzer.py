"""
PhishNetra - Secure Form & Credential Harvest Analysis Engine
Module: services.ml.app.analyzer.form_analyzer
Milestone: 3
"""

import urllib.parse
import re
from typing import Dict, Any, List


class FormAnalyzer:
    """
    Form Inspector detecting credential phishing, cross-origin action submissions,
    and sensitive data fields.
    """

    PASSWORD_PATTERNS = re.compile(r"pass|pwd|secret|auth|token|pin|security_code", re.IGNORECASE)
    EMAIL_PATTERNS = re.compile(r"email|e-mail|mail|username|user|login|id|identifier", re.IGNORECASE)
    CC_PATTERNS = re.compile(r"card|credit|cvv|cvc|expir|cc_num|account_num", re.IGNORECASE)
    OTP_PATTERNS = re.compile(r"otp|2fa|mfa|verification|code|sms_code", re.IGNORECASE)

    @classmethod
    def analyze_forms(cls, forms: List[Dict[str, Any]], base_url: str) -> List[Dict[str, Any]]:
        base_host = ""
        base_reg_domain = ""
        try:
            parsed_base = urllib.parse.urlsplit(base_url)
            base_host = parsed_base.netloc.lower()
            parts = base_host.split(".")
            base_reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else base_host
        except Exception:
            pass

        findings: List[Dict[str, Any]] = []

        for idx, form in enumerate(forms):
            raw_action = form.get("action", "").strip()
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            # Resolve absolute action
            if not raw_action:
                action_resolved = base_url
            else:
                action_resolved = urllib.parse.urljoin(base_url, raw_action)

            # Check action domain
            is_cross_origin = False
            is_ip_action = False
            action_host = ""
            try:
                parsed_action = urllib.parse.urlsplit(action_resolved)
                action_host = parsed_action.netloc.lower().split(":")[0]
                if action_host:
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", action_host):
                        is_ip_action = True

                    action_parts = action_host.split(".")
                    action_reg_domain = ".".join(action_parts[-2:]) if len(action_parts) >= 2 else action_host

                    if base_reg_domain and action_reg_domain and base_reg_domain != action_reg_domain:
                        is_cross_origin = True
            except Exception:
                pass

            has_password = False
            has_email = False
            has_cc = False
            has_otp = False
            password_count = 0

            for inp in inputs:
                t = inp.get("type", "").lower()
                name = inp.get("name", "")
                inp_id = inp.get("id", "")
                placeholder = inp.get("placeholder", "")
                autocomplete = inp.get("autocomplete", "")

                text_combined = f"{name} {inp_id} {placeholder} {autocomplete}"

                if t == "password" or cls.PASSWORD_PATTERNS.search(text_combined):
                    has_password = True
                    password_count += 1
                elif t in ("email", "text") and cls.EMAIL_PATTERNS.search(text_combined):
                    has_email = True

                if cls.CC_PATTERNS.search(text_combined):
                    has_cc = True
                if cls.OTP_PATTERNS.search(text_combined):
                    has_otp = True

            description_parts = []
            if has_password:
                description_parts.append("requests password credentials")
            if has_email:
                description_parts.append("requests user identity")
            if has_cc:
                description_parts.append("requests financial card details")
            if has_otp:
                description_parts.append("requests OTP/2FA verification code")

            if is_cross_origin:
                description_parts.append(f"submits data to external domain ({action_host})")
            elif is_ip_action:
                description_parts.append(f"submits data to raw IP address ({action_host})")

            desc = f"Form #{idx + 1} " + (", ".join(description_parts) if description_parts else "standard data form")

            findings.append({
                "id": form.get("id") or f"form_{idx}",
                "name": form.get("name", ""),
                "action": raw_action,
                "actionResolved": action_resolved,
                "method": method,
                "target": form.get("target", ""),
                "isCrossOrigin": is_cross_origin,
                "isIpAction": is_ip_action,
                "hasPasswordField": has_password,
                "hasEmailField": has_email,
                "hasCreditCardField": has_cc,
                "hasOtpField": has_otp,
                "passwordFieldCount": password_count,
                "inputCount": len(inputs),
                "description": desc
            })

        return findings


form_analyzer = FormAnalyzer()
