"""Testes do carregamento de configuracao (config.settings)."""

from __future__ import annotations


from config.settings import DEFAULT_CONFIG_PATH, load_settings


def test_load_settings_from_default_config_yaml() -> None:
    settings = load_settings(DEFAULT_CONFIG_PATH)

    assert settings.database.url.startswith("sqlite:")
    assert len(settings.collectors.render_profiles) == 5
    assert settings.correlation.weights.same_fingerprint == 35
    assert settings.correlation.thresholds.medium_confidence_max == 69
    assert any(brand.name == "itau" for brand in settings.brands.known_brands)


def test_env_override_replaces_misp_api_key(monkeypatch) -> None:
    monkeypatch.setenv("PHISHING_INTEL_MISP__API_KEY", "OVERRIDDEN-KEY")
    settings = load_settings(DEFAULT_CONFIG_PATH)
    assert settings.misp.api_key == "OVERRIDDEN-KEY"
    monkeypatch.delenv("PHISHING_INTEL_MISP__API_KEY", raising=False)


def test_confidence_level_thresholds() -> None:
    from models.campaign import ConfidenceLevel

    assert ConfidenceLevel.from_score(0) == ConfidenceLevel.LOW
    assert ConfidenceLevel.from_score(39) == ConfidenceLevel.LOW
    assert ConfidenceLevel.from_score(40) == ConfidenceLevel.MEDIUM
    assert ConfidenceLevel.from_score(69) == ConfidenceLevel.MEDIUM
    assert ConfidenceLevel.from_score(70) == ConfidenceLevel.HIGH
    assert ConfidenceLevel.from_score(100) == ConfidenceLevel.HIGH
