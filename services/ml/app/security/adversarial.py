"""
PhishNetra - Adversarial Hardening & Evasion Robustness Engine
Module: services.ml.app.security.adversarial
Milestone: 7
"""

import re
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, urlunparse

from app.core.schemas import (
    AdversarialAttackResultModel,
    AdversarialEvaluationResponse
)
from app.models.baseline import model_service


# Cyrillic to Latin homoglyph mappings
HOMOGLYPH_MAP = {
    'a': 'а',  # Cyrillic small letter a (\u0430)
    'c': 'с',  # Cyrillic small letter es (\u0441)
    'e': 'е',  # Cyrillic small letter ie (\u0435)
    'o': 'о',  # Cyrillic small letter o (\u043e)
    'p': 'р',  # Cyrillic small letter er (\u0440)
    's': 'ѕ',  # Cyrillic small letter dze (\u0455)
    'x': 'х',  # Cyrillic small letter ha (\u0445)
    'y': 'у',  # Cyrillic small letter u (\u0443)
    'i': 'і',  # Cyrillic small letter byelorussian-ukrainian i (\u0456)
}


class AdversarialPerturbationEngine:
    """
    Generates realistic adversarial evasion attacks against URL lexical feature extractors.
    """

    @staticmethod
    def apply_homoglyph(url: str) -> str:
        """Substitutes select Latin letters in the domain with Cyrillic homoglyphs."""
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc
            new_chars = []
            replaced = False
            for char in netloc:
                if not replaced and char.lower() in HOMOGLYPH_MAP:
                    new_chars.append(HOMOGLYPH_MAP[char.lower()])
                    replaced = True
                else:
                    new_chars.append(char)
            new_netloc = "".join(new_chars)
            return urlunparse(parsed._replace(netloc=new_netloc))
        except Exception:
            return url

    @staticmethod
    def apply_keyword_stuffing(url: str) -> str:
        """Appends benign, high-reputation paths to dilute lexical risk."""
        suffix = "/docs/legal/privacy-policy/terms/help/about-us/verified-support/whitepaper.html"
        return url.rstrip("/") + suffix

    @staticmethod
    def apply_subdomain_packing(url: str) -> str:
        """Prepends deep legitimate-looking subdomains."""
        try:
            parsed = urlparse(url)
            prefix = "sso.identity.okta.auth.secure-portal.login."
            new_netloc = prefix + parsed.netloc
            return urlunparse(parsed._replace(netloc=new_netloc))
        except Exception:
            return url

    @staticmethod
    def apply_tld_masquerade(url: str) -> str:
        """Appends brand name before obscure pseudo-TLDs."""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            new_host = f"{host}-official-verification.co.vu"
            return urlunparse(parsed._replace(netloc=new_host))
        except Exception:
            return url

    @staticmethod
    def apply_length_inflation(url: str) -> str:
        """Pads query parameters with arbitrary benign-looking tokens."""
        delimiter = "&" if "?" in url else "?"
        padding = (
            "utm_source=trusted_enterprise_partner&utm_medium=verified_sso_gateway"
            "&session_payload_token=8923749823479238479238479283479283749823749823749823749823749283749823749823"
        )
        return f"{url}{delimiter}{padding}"

    @staticmethod
    def apply_encoding_trick(url: str) -> str:
        """Converts key characters to percent-encoded hex sequences."""
        try:
            parsed = urlparse(url)
            path = parsed.path or "/"
            # Encode 'a' -> %61, 'e' -> %65, 'o' -> %6f
            encoded_path = path.replace("a", "%61").replace("e", "%65").replace("o", "%6f")
            return urlunparse(parsed._replace(path=encoded_path))
        except Exception:
            return url

    def perturb(self, url: str, attack_type: str) -> str:
        """Dispatches perturbation for given attack type."""
        mapping = {
            "HOMOGLYPH": self.apply_homoglyph,
            "KEYWORD_STUFFING": self.apply_keyword_stuffing,
            "SUBDOMAIN_PACKING": self.apply_subdomain_packing,
            "TLD_MASQUERADE": self.apply_tld_masquerade,
            "LENGTH_INFLATION": self.apply_length_inflation,
            "ENCODING_TRICK": self.apply_encoding_trick,
        }
        func = mapping.get(attack_type.upper(), self.apply_homoglyph)
        return func(url)

    def evaluate_url(self, target_url: str, attack_types: Optional[List[str]] = None) -> List[AdversarialAttackResultModel]:
        """Runs adversarial perturbations against a single URL and tests model robustness."""
        if attack_types is None:
            attack_types = [
                "HOMOGLYPH",
                "KEYWORD_STUFFING",
                "SUBDOMAIN_PACKING",
                "TLD_MASQUERADE",
                "LENGTH_INFLATION",
                "ENCODING_TRICK"
            ]

        orig_pred = model_service.predict(target_url)
        orig_score = round(orig_pred.phishing_probability * 100.0, 2)

        results: List[AdversarialAttackResultModel] = []

        for atk in attack_types:
            perturbed = self.perturb(target_url, atk)
            pert_pred = model_service.predict(perturbed)
            pert_score = round(pert_pred.phishing_probability * 100.0, 2)

            # Evasion is true if original URL was flagged (>= 50), but perturbation drops below 50
            is_evaded = (orig_score >= 50.0 and pert_score < 50.0)
            score_diff = round(orig_score - pert_score, 2)

            results.append(
                AdversarialAttackResultModel(
                    attackType=atk,
                    originalUrl=target_url,
                    perturbedUrl=perturbed,
                    originalScore=orig_score,
                    perturbedScore=pert_score,
                    evaded=is_evaded,
                    scoreDiff=score_diff
                )
            )

        return results

    def run_suite(self, urls: Optional[List[str]] = None) -> AdversarialEvaluationResponse:
        """Executes full adversarial robustness suite across test samples."""
        if not urls:
            urls = [
                "http://192.168.1.1/login.php?user=admin",
                "https://paypal.com.verify-account-update.xyz/signin",
                "http://secure-chase-banking-portal.top/auth/login",
                "https://apple-id-verify.update-suspended-account.live/security",
                "https://bankofamerica.com-login-verify.site/account"
            ]

        all_results: List[AdversarialAttackResultModel] = []
        for u in urls:
            res = self.evaluate_url(u)
            all_results.extend(res)

        total = len(all_results)
        evaded_count = sum(1 for r in all_results if r.evaded)
        evasion_rate = round(evaded_count / max(1, total), 4)
        robustness_score = round(max(0.0, (1.0 - evasion_rate) * 100.0), 2)

        if evasion_rate <= 0.15:
            status = "ROBUST"
        elif evasion_rate <= 0.40:
            status = "VULNERABLE"
        else:
            status = "CRITICAL_DEFICIT"

        return AdversarialEvaluationResponse(
            testedAt=datetime.utcnow().isoformat() + "Z",
            totalTests=total,
            evasionRate=evasion_rate,
            overallRobustnessScore=robustness_score,
            results=all_results,
            hardeningStatus=status
        )


adversarial_engine = AdversarialPerturbationEngine()
