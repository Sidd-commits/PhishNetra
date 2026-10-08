"""
Unit Tests for Data Drift & PSI Detection Engine
Module: services.ml.tests.test_drift_detector
Milestone: 7
"""

import pytest
import numpy as np
from app.mlops.drift_detector import drift_detector


def test_psi_calculation_identical_distributions():
    data = np.random.normal(50, 10, 100)
    psi = drift_detector.calculate_psi(data, data)
    assert 0.0 <= psi < 0.05  # Identical data should have ~0 PSI


def test_psi_calculation_divergent_distributions():
    expected = np.random.normal(10, 2, 200)
    actual = np.random.normal(50, 10, 200)
    psi = drift_detector.calculate_psi(expected, actual)
    assert psi > 0.25  # Substantial divergence should yield high PSI


def test_drift_report_structure():
    report = drift_detector.evaluate_drift()
    assert report.overallDriftStatus in ("STABLE", "MODERATE", "CRITICAL")
    assert report.baselineSamples > 0
    assert report.liveSamples > 0
    assert len(report.features) > 10
    assert len(report.recommendation) > 10

    for f in report.features:
        assert 0.0 <= f.psiScore
        assert 0.0 <= f.ksStatistic <= 1.0
        assert 0.0 <= f.pValue <= 1.0
        assert f.status in ("STABLE", "MODERATE", "DRIFTED")
