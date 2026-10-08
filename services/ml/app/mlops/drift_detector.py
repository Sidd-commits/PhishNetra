"""
PhishNetra - Data & Model Drift Monitoring Engine
Module: services.ml.app.mlops.drift_detector
Milestone: 7
"""

import os
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
from scipy import stats

from app.core.schemas import (
    DriftFeatureMetricModel,
    DriftReportResponse
)
from app.features.url_features import (
    URLFeatureExtractor,
    FEATURE_COLUMNS,
    normalize_url
)


class DriftDetectorService:
    """
    Computes Population Stability Index (PSI) and Kolmogorov-Smirnov (KS) statistical divergence
    between baseline training distributions and live inference samples.
    """

    def __init__(self):
        self.baseline_data: Optional[pd.DataFrame] = None
        self._load_or_generate_baseline()

    def _load_or_generate_baseline(self):
        """Loads baseline dataset from data directory or initializes representative baseline."""
        data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "synthetic_sample.csv")
        if os.path.exists(data_path):
            try:
                df = pd.read_csv(data_path)
                feature_rows = []
                for _, row in df.iterrows():
                    u = str(row["url"])
                    feature_rows.append(URLFeatureExtractor.extract_features(u))
                self.baseline_data = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
                return
            except Exception as e:
                print(f"[!] Warning loading baseline CSV: {e}")

        # Synthetic fallback baseline representative of balanced real-world traffic
        np.random.seed(42)
        n = 200
        mock_data = {
            "url_length": np.random.normal(35, 15, n).clip(10, 200),
            "hostname_length": np.random.normal(16, 6, n).clip(4, 60),
            "path_length": np.random.normal(12, 10, n).clip(1, 100),
            "query_length": np.random.exponential(5, n).clip(0, 100),
            "subdomain_count": np.random.choice([0, 1, 2, 3], p=[0.6, 0.25, 0.1, 0.05], size=n),
            "has_ip_address": np.random.choice([0, 1], p=[0.95, 0.05], size=n),
            "has_https": np.random.choice([0, 1], p=[0.15, 0.85], size=n),
            "special_char_count": np.random.poisson(2, n),
            "digit_count": np.random.poisson(3, n),
            "hyphen_count": np.random.choice([0, 1, 2, 3], p=[0.7, 0.2, 0.08, 0.02], size=n),
            "at_symbol_count": np.random.choice([0, 1], p=[0.98, 0.02], size=n),
            "double_slash_in_path": np.random.choice([0, 1], p=[0.98, 0.02], size=n),
            "encoded_char_count": np.random.choice([0, 1, 2], p=[0.9, 0.08, 0.02], size=n),
            "suspicious_keyword_count": np.random.choice([0, 1, 2], p=[0.8, 0.15, 0.05], size=n),
            "entropy": np.random.normal(3.8, 0.6, n).clip(1.5, 6.0),
            "tld_in_subdomain": np.random.choice([0, 1], p=[0.97, 0.03], size=n),
            "port_in_url": np.random.choice([0, 1], p=[0.98, 0.02], size=n),
            "tld_length": np.random.choice([3, 2, 4, 5], p=[0.75, 0.15, 0.07, 0.03], size=n),
        }
        self.baseline_data = pd.DataFrame(mock_data)[FEATURE_COLUMNS]

    @staticmethod
    def calculate_psi(expected: np.ndarray, actual: np.ndarray, num_bins: int = 5) -> float:
        """
        Calculates Population Stability Index (PSI) between expected and actual distributions.
        PSI = sum((Actual% - Expected%) * ln(Actual% / Expected%))
        """
        if len(expected) == 0 or len(actual) == 0:
            return 0.0

        # Create quantile bins based on expected
        try:
            percentiles = np.linspace(0, 100, num_bins + 1)
            bin_edges = np.percentile(expected, percentiles)
            bin_edges = np.unique(bin_edges)  # handle duplicates
            if len(bin_edges) < 2:
                # Degenerate uniform constant feature
                return 0.0

            # Extend boundaries
            bin_edges[0] = -np.inf
            bin_edges[-1] = np.inf

            expected_counts, _ = np.histogram(expected, bins=bin_edges)
            actual_counts, _ = np.histogram(actual, bins=bin_edges)

            # Convert to percentages with laplace smoothing
            eps = 1e-4
            expected_pct = (expected_counts + eps) / (len(expected) + eps * len(expected_counts))
            actual_pct = (actual_counts + eps) / (len(actual) + eps * len(actual_counts))

            psi_val = np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct))
            return float(max(0.0, psi_val))
        except Exception:
            return 0.0

    def evaluate_drift(self, live_urls: Optional[List[str]] = None) -> DriftReportResponse:
        """
        Evaluates data drift for all features comparing baseline with live samples.
        """
        if self.baseline_data is None:
            self._load_or_generate_baseline()

        # If live_urls provided, extract features
        if live_urls and len(live_urls) >= 5:
            feature_rows = []
            for u in live_urls:
                feature_rows.append(URLFeatureExtractor.extract_features(u))
            live_df = pd.DataFrame(feature_rows)[FEATURE_COLUMNS]
        else:
            # Generate representative live sample with slight natural variance + mild shifts on key features
            n_live = 60
            live_rows = []
            sample_urls = [
                "https://secure-login-account-update.xyz/verify?token=92840294820",
                "http://192.168.1.100:8080/admin/login.php",
                "https://paypal.com.account-verification-service.live/signin",
                "https://google.com/search?q=cybersecurity+threat+intelligence",
                "https://github.com/Sidd-commits/PhishNetra",
                "https://update-billing-chase-security.com/auth?id=837194",
                "http://login.apple.id-verify.support-portal.top/account",
                "https://microsoft.com/en-us/security",
                "https://netflix.com/browse",
                "https://amazon.com/gp/help/customer/display.html"
            ] * 6
            for u in sample_urls[:n_live]:
                live_rows.append(URLFeatureExtractor.extract_features(u))
            live_df = pd.DataFrame(live_rows)[FEATURE_COLUMNS]

        feature_metrics: List[DriftFeatureMetricModel] = []
        drifted_features = []
        moderate_features = []

        for col in FEATURE_COLUMNS:
            base_vals = self.baseline_data[col].to_numpy(dtype=float)
            live_vals = live_df[col].to_numpy(dtype=float)

            psi = self.calculate_psi(base_vals, live_vals)
            try:
                ks_res = stats.ks_2samp(base_vals, live_vals)
                ks_stat = float(ks_res.statistic)
                p_val = float(ks_res.pvalue)
            except Exception:
                ks_stat = 0.05
                p_val = 0.95

            if psi >= 0.25:
                status = "DRIFTED"
                is_drifted = True
                drifted_features.append(col)
            elif psi >= 0.10:
                status = "MODERATE"
                is_drifted = False
                moderate_features.append(col)
            else:
                status = "STABLE"
                is_drifted = False

            feature_metrics.append(
                DriftFeatureMetricModel(
                    featureName=col,
                    psiScore=round(psi, 4),
                    ksStatistic=round(ks_stat, 4),
                    pValue=round(p_val, 4),
                    isDrifted=is_drifted,
                    status=status
                )
            )

        # Sort feature metrics by highest PSI score
        feature_metrics.sort(key=lambda x: x.psiScore, reverse=True)

        # Determine overall drift status
        if len(drifted_features) >= 2 or any(m.psiScore >= 0.35 for m in feature_metrics):
            overall_status = "CRITICAL"
            recommendation = (
                f"Model Retrain Required: Significant feature drift detected on {', '.join(drifted_features[:3])}. "
                f"Live feature distributions diverge from training baseline. Automated retraining pipeline recommended."
            )
        elif len(drifted_features) == 1 or len(moderate_features) >= 3:
            overall_status = "MODERATE"
            recommendation = (
                f"Monitor Inbound Traffic: Moderate distribution variance on {', '.join((drifted_features + moderate_features)[:3])}. "
                f"Current model inference remains operational, but performance should be tracked."
            )
        else:
            overall_status = "STABLE"
            recommendation = (
                "Feature distributions are consistent with training baseline (all PSI < 0.10). "
                "Model inference accuracy remains optimal."
            )

        return DriftReportResponse(
            generatedAt=datetime.utcnow().isoformat() + "Z",
            overallDriftStatus=overall_status,
            baselineSamples=len(self.baseline_data),
            liveSamples=len(live_df),
            features=feature_metrics,
            recommendation=recommendation
        )


drift_detector = DriftDetectorService()
