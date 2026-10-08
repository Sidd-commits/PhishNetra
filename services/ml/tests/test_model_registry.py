"""
Unit Tests for Model Registry & Dynamic Hot-Swapping
Module: services.ml.tests.test_model_registry
Milestone: 7
"""

import pytest
from app.models.registry import model_registry
from app.core.schemas import ModelMetadataModel


def test_model_registry_overview():
    overview = model_registry.get_overview()
    assert overview.totalModels >= 1
    assert overview.activeModel is not None
    assert "baseline" in overview.activeModel.version or "retrained" in overview.activeModel.version
    assert 0.0 <= overview.activeModel.accuracy <= 1.0


def test_model_registry_get_model():
    overview = model_registry.get_overview()
    active_version = overview.activeModel.version
    model = model_registry.get_model(active_version)
    assert model is not None
    assert model.version == active_version
    assert model.active is True


def test_model_registry_activate_model():
    overview = model_registry.get_overview()
    active_version = overview.activeModel.version
    # Re-activating the active model should succeed
    res = model_registry.activate_model(active_version)
    assert res.success is True
    assert res.activeModel.version == active_version
