"""Unit tests for configuration loading + environment overrides."""

from __future__ import annotations

from pathlib import Path

from phishing_intel.config.settings import load_settings


def test_load_bundled_settings_defaults() -> None:
    """The bundled config.yaml should load and validate."""

    settings = load_settings()
    assert settings.app.name == "phishing-intel"
    assert settings.correlation.weights["same_fingerprint"] >= 1
    assert settings.correlation.thresholds.high_min == 70


def test_load_missing_file_yields_defaults(tmp_path: Path) -> None:
    """A non-existent path falls back to model defaults."""

    settings = load_settings(tmp_path / "does-not-exist.yaml")
    assert settings.app.name == "phishing-intel"
    assert settings.misp.enabled is False


def test_env_override_scalar_coercion(tmp_path: Path, monkeypatch) -> None:
    """PHISHINTEL_ env vars override nested keys with type coercion."""

    cfg = tmp_path / "c.yaml"
    cfg.write_text("misp:\n  enabled: false\n  threat_level_id: 2\n", encoding="utf-8")
    monkeypatch.setenv("PHISHINTEL_MISP__ENABLED", "true")
    monkeypatch.setenv("PHISHINTEL_MISP__THREAT_LEVEL_ID", "1")
    monkeypatch.setenv("PHISHINTEL_MISP__URL", "https://override.local")

    settings = load_settings(cfg)
    assert settings.misp.enabled is True  # coerced bool
    assert settings.misp.threat_level_id == 1  # coerced int
    assert settings.misp.url == "https://override.local"  # string


def test_env_override_creates_nested_structure(tmp_path: Path, monkeypatch) -> None:
    """Overrides work even when the section is absent from the YAML."""

    cfg = tmp_path / "c.yaml"
    cfg.write_text("app:\n  name: base\n", encoding="utf-8")
    monkeypatch.setenv("PHISHINTEL_DATABASE__URL", "sqlite:///x.db")
    settings = load_settings(cfg)
    assert settings.database.url == "sqlite:///x.db"
