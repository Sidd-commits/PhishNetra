"""
PhishNetra - Brand Impersonation & Social Engineering Analysis Engine
Module: services.ml.app.analyzer.brand_analyzer
Milestone: 3
"""

import re
import urllib.parse
from typing import Dict, Any, List, Tuple


KNOWN_BRANDS = {
    "Microsoft": {
        "keywords": ["microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint", "azure", "live.com", "msn"],
        "domains": ["microsoft.com", "live.com", "office.com", "outlook.com", "azure.com", "msn.com", "sharepoint.com", "microsoftonline.com", "windows.net"]
    },
    "Google": {
        "keywords": ["google", "gmail", "google drive", "google docs", "google workspace", "youtube"],
        "domains": ["google.com", "gmail.com", "youtube.com", "google.co.in", "google.co.uk", "google.ca", "google.de", "google.fr", "1e100.net"]
    },
    "Apple": {
        "keywords": ["apple", "icloud", "apple id", "itunes", "app store"],
        "domains": ["apple.com", "icloud.com"]
    },
    "Amazon": {
        "keywords": ["amazon", "prime video", "aws", "amazon web services", "amazon pay"],
        "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp", "amazon.fr", "aws.amazon.com"]
    },
    "PayPal": {
        "keywords": ["paypal", "paypal me", "paypal invoice"],
        "domains": ["paypal.com", "paypal.me"]
    },
    "Netflix": {
        "keywords": ["netflix", "netflix membership", "netflix streaming"],
        "domains": ["netflix.com"]
    },
    "Meta / Facebook": {
        "keywords": ["facebook", "instagram", "whatsapp", "meta", "messenger"],
        "domains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com", "fb.com"]
    },
    "Bank of America": {
        "keywords": ["bank of america", "bofa", "merrill lynch"],
        "domains": ["bankofamerica.com", "bofa.com", "merrilledge.com"]
    },
    "Chase": {
        "keywords": ["chase bank", "jpmorgan chase", "chase online"],
        "domains": ["chase.com", "jpmorganchase.com", "jpmorgan.com"]
    },
    "Wells Fargo": {
        "keywords": ["wells fargo", "wellsfargo"],
        "domains": ["wellsfargo.com"]
    },
    "DHL": {
        "keywords": ["dhl express", "dhl tracking", "dhl delivery", "dhl shipment"],
        "domains": ["dhl.com", "dhl.de"]
    },
    "FedEx": {
        "keywords": ["fedex express", "fedex tracking", "fedex delivery"],
        "domains": ["fedex.com"]
    },
    "USPS": {
        "keywords": ["usps", "postal service", "usps tracking"],
        "domains": ["usps.com"]
    },
    "Dropbox": {
        "keywords": ["dropbox", "dropbox business"],
        "domains": ["dropbox.com"]
    },
    "Adobe": {
        "keywords": ["adobe", "creative cloud", "acrobat", "adobe document cloud"],
        "domains": ["adobe.com"]
    }
}

KEYWORD_CATEGORIES = {
    "authentication": [
        "login", "sign in", "sign-in", "signin", "log in", "verify your account",
        "confirm your identity", "password reset", "security key", "credentials",
        "enter your password", "user id", "passcode"
    ],
    "banking": [
        "bank", "credit card", "debit card", "account balance", "cvv", "routing number",
        "checking account", "card number", "card expiry", "wire transfer", "wallet"
    ],
    "security_alert": [
        "account suspended", "unusual activity", "security alert", "unauthorized access",
        "account locked", "compromised", "identity verification required", "threat detected"
    ],
    "payment": [
        "invoice", "payment failed", "billing update", "remit payment", "declined transaction",
        "overdue balance", "subscription expired", "payment problem"
    ],
    "urgency": [
        "urgent", "immediately", "action required", "within 24 hours", "expires today",
        "limited time", "act now", "final notice", "immediate action", "24 hours"
    ]
}


class BrandConsistencyAnalyzer:
    """
    Analyzes brand consistency and social engineering signals across page title,
    visible text, form descriptors, and target hostname.
    """

    @classmethod
    def get_registrable_domain(cls, hostname: str) -> str:
        clean_host = hostname.lower().split(":")[0].strip(".")
        parts = clean_host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return clean_host

    @classmethod
    def analyze(cls, base_url: str, title: str, visible_text: str, forms: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], float]:
        """
        Returns: (brand_findings, keyword_findings, urgency_score)
        """
        host = ""
        try:
            host = urllib.parse.urlsplit(base_url).netloc.lower().split(":")[0]
        except Exception:
            pass

        target_reg_domain = cls.get_registrable_domain(host)

        corpus_title = title.lower()
        corpus_text = visible_text.lower()
        corpus_forms = " ".join([f.get("description", "") for f in forms]).lower()
        combined_corpus = f"{corpus_title} {corpus_text} {corpus_forms}"

        brand_findings: List[Dict[str, Any]] = []

        for brand_name, brand_data in KNOWN_BRANDS.items():
            matched_sources = []
            brand_hits = 0

            for kw in brand_data["keywords"]:
                pattern = r"\b" + re.escape(kw) + r"\b"
                if re.search(pattern, corpus_title):
                    matched_sources.append(f"Title contains '{kw}'")
                    brand_hits += 3
                if re.search(pattern, corpus_forms):
                    matched_sources.append(f"Form contains '{kw}'")
                    brand_hits += 2
                if re.search(pattern, corpus_text):
                    brand_hits += 1

            if brand_hits >= 2:
                # Brand is claimed/referenced on the page
                is_authentic = any(
                    target_reg_domain == d or target_reg_domain.endswith("." + d)
                    for d in brand_data["domains"]
                )

                is_mismatch = not is_authentic
                confidence = min(1.0, 0.5 + (brand_hits * 0.1))

                desc = (
                    f"Page strongly references '{brand_name}' but is hosted on unrelated domain '{target_reg_domain}' (Expected: {brand_data['domains'][0]})."
                    if is_mismatch
                    else f"Page references '{brand_name}' on verified authentic domain '{target_reg_domain}'."
                )

                brand_findings.append({
                    "claimedBrand": brand_name,
                    "authenticDomain": brand_data["domains"][0],
                    "actualDomain": target_reg_domain,
                    "isMismatch": is_mismatch,
                    "confidence": round(confidence, 2),
                    "matchSources": matched_sources,
                    "description": desc
                })

        # Phishing Keywords Categorization
        keyword_findings: List[Dict[str, Any]] = []
        total_urgency_hits = 0

        for category, term_list in KEYWORD_CATEGORIES.items():
            cat_matches = []
            for term in term_list:
                pattern = r"\b" + re.escape(term) + r"\b"
                count = len(re.findall(pattern, combined_corpus))
                if count > 0:
                    cat_matches.append(term)
                    if category == "urgency":
                        total_urgency_hits += count

            if cat_matches:
                keyword_findings.append({
                    "category": category,
                    "count": len(cat_matches),
                    "matchedTerms": cat_matches[:10]
                })

        # Compute Urgency / Social Engineering score (0.0 to 1.0)
        urgency_score = min(1.0, round(total_urgency_hits * 0.25, 2))

        return brand_findings, keyword_findings, urgency_score


brand_analyzer = BrandConsistencyAnalyzer()
