"""
PhishNetra - Deterministic URL Feature Extraction Engine
Module: services.ml.app.features.url_features
Milestone: 1
"""

import math
import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse, unquote


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "security",
    "secure", "account", "banking", "bank", "paypal", "wallet", "password",
    "credential", "auth", "confirm", "suspended", "recover", "restore",
    "support", "service", "billing", "alert", "kyc", "claim", "free", "gift"
]

COMMON_TLDS = [
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "app", "dev",
    "xyz", "top", "cc", "club", "online", "site", "live", "info", "biz"
]

FEATURE_COLUMNS: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "has_ip_address",
    "has_https",
    "special_char_count",
    "digit_count",
    "hyphen_count",
    "at_symbol_count",
    "double_slash_in_path",
    "encoded_char_count",
    "suspicious_keyword_count",
    "entropy",
    "tld_in_subdomain",
    "port_in_url",
    "tld_length",
]


def normalize_url(raw_url: str) -> str:
    """
    Canonicalizes and normalizes a given URL.
    - Strips whitespace
    - Ensures scheme is present (defaults to http:// if missing)
    - Lowercases hostname
    - Cleans default ports
    """
    if not raw_url:
        return ""
    
    url = raw_url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
        
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        
        # Remove standard default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
            
        path = parsed.path or "/"
        query = f"?{parsed.query}" if parsed.query else ""
        fragment = f"#{parsed.fragment}" if parsed.fragment else ""
        
        return f"{scheme}://{netloc}{path}{query}{fragment}"
    except Exception:
        return raw_url


def calculate_entropy(text: str) -> float:
    """
    Calculates the Shannon entropy of a given text string.
    Higher entropy often indicates randomness, obfuscation, or hash-like patterns.
    """
    if not text:
        return 0.0
    
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
        
    entropy = 0.0
    text_len = len(text)
    for count in char_counts.values():
        p = count / text_len
        entropy -= p * math.log2(p)
        
    return round(entropy, 4)


def is_ip_address(hostname: str) -> int:
    """
    Checks if hostname is an IPv4 or IPv6 address.
    """
    # Remove port if present
    host = hostname.split(":")[0] if ":" in hostname else hostname
    
    # IPv4 regex check
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        parts = host.split(".")
        if all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
            return 1
            
    # IPv6 check
    if ":" in host and len(host) > 2:
        return 1
        
    return 0


class URLFeatureExtractor:
    """
    Deterministic URL Feature Extraction class.
    Extracts structural, lexical, and statistical signals from URLs without making network requests.
    """

    @classmethod
    def extract_features(cls, raw_url: str) -> Dict[str, Any]:
        """
        Extracts all dictionary features from a raw URL.
        """
        canonical_url = normalize_url(raw_url)
        parsed = urlparse(canonical_url)
        
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        scheme = parsed.scheme.lower()
        
        # 1. Length features
        url_length = len(canonical_url)
        hostname_length = len(hostname)
        path_length = len(path)
        query_length = len(query)
        
        # 2. Hostname / Domain features
        host_parts = hostname.split(".")
        if len(host_parts) > 2:
            # e.g., sub1.sub2.example.com -> subdomain_count = 2
            subdomain_count = len(host_parts) - 2
        else:
            subdomain_count = 0
            
        tld = host_parts[-1] if host_parts else ""
        tld_length = len(tld)
        
        # Check if a known TLD is embedded within subdomain (e.g. paypal.com.attacker.xyz)
        tld_in_sub = 0
        if subdomain_count > 0:
            subdomain_str = ".".join(host_parts[:-2])
            for known_tld in COMMON_TLDS:
                if f".{known_tld}" in subdomain_str or subdomain_str.endswith(known_tld):
                    tld_in_sub = 1
                    break

        has_ip = is_ip_address(hostname)
        has_https = 1 if scheme == "https" else 0
        port_in_url = 1 if parsed.port is not None else 0
        
        # 3. Lexical / Character features
        special_chars = set("@-_=?%&*!~+")
        special_char_count = sum(1 for c in canonical_url if c in special_chars)
        digit_count = sum(1 for c in canonical_url if c.isdigit())
        hyphen_count = hostname.count("-")
        at_symbol_count = canonical_url.count("@")
        double_slash_in_path = 1 if "//" in path else 0
        encoded_char_count = canonical_url.count("%")
        
        # 4. Suspicious keywords count in hostname and path
        target_text = f"{hostname}{path}".lower()
        suspicious_keyword_count = sum(
            1 for kw in SUSPICIOUS_KEYWORDS if kw in target_text
        )
        
        # 5. Shannon Entropy
        entropy = calculate_entropy(canonical_url)
        
        return {
            "url_length": url_length,
            "hostname_length": hostname_length,
            "path_length": path_length,
            "query_length": query_length,
            "subdomain_count": subdomain_count,
            "has_ip_address": has_ip,
            "has_https": has_https,
            "special_char_count": special_char_count,
            "digit_count": digit_count,
            "hyphen_count": hyphen_count,
            "at_symbol_count": at_symbol_count,
            "double_slash_in_path": double_slash_in_path,
            "encoded_char_count": encoded_char_count,
            "suspicious_keyword_count": suspicious_keyword_count,
            "entropy": entropy,
            "tld_in_subdomain": tld_in_sub,
            "port_in_url": port_in_url,
            "tld_length": tld_length,
        }

    @classmethod
    def extract_vector(cls, raw_url: str) -> List[float]:
        """
        Extracts an ordered numerical vector matching FEATURE_COLUMNS for ML model inference.
        """
        features = cls.extract_features(raw_url)
        return [float(features[col]) for col in FEATURE_COLUMNS]
