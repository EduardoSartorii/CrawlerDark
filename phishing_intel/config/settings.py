"""Typed configuration models and loader.

Responsibility
--------------
Turn the human-friendly ``config.yaml`` file into a validated, immutable-ish
Pydantic object graph so the rest of the codebase never has to guess at the
shape of the configuration. Environment variables may override any value using
the ``PHISHINTEL_`` prefix and ``__`` as the nesting delimiter, which is the
convention expected by containerised / secret-managed deployments.

Execution flow
--------------
``load_settings(path)`` -> read YAML -> deep-merge environment overrides ->
validate through :class:`Settings` -> return the object.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml
from pydantic import BaseModel, Field

# Default location of the bundled configuration file (relative to this module).
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"

# Prefix + delimiter used for environment-variable overrides.
_ENV_PREFIX = "PHISHINTEL_"
_ENV_DELIMITER = "__"


class AppSettings(BaseModel):
    """General application behaviour."""

    name: str = "phishing-intel"
    evidence_dir: str = "./evidence"
    allow_network: bool = True


class LoggingSettings(BaseModel):
    """Structured logging configuration."""

    level: str = "INFO"
    format: str = "console"  # "console" | "json"


class DatabaseSettings(BaseModel):
    """Relational persistence configuration."""

    url: str = "sqlite:///phishing_intel.db"
    echo: bool = False


class MISPSettings(BaseModel):
    """MISP enrichment integration configuration."""

    enabled: bool = False
    url: str = "https://misp.local"
    key: str = "CHANGE-ME"
    verify_cert: bool = True
    distribution: int = 0
    threat_level_id: int = 2
    analysis: int = 2


class CorrelationThresholds(BaseModel):
    """Confidence classification thresholds for the attribution score."""

    low: int = 39
    medium: int = 69
    high_min: int = 70


class CorrelationSettings(BaseModel):
    """Correlation / attribution engine tunables."""

    # Individual signal weights; summed then normalised to 0-100.
    weights: Dict[str, int] = Field(
        default_factory=lambda: {
            "same_fingerprint": 40,
            "same_certificate": 25,
            "same_asn": 15,
            "same_provider": 10,
            "same_dom_pattern": 20,
            "same_js_pattern": 15,
            "same_brand": 10,
        }
    )
    thresholds: CorrelationThresholds = Field(default_factory=CorrelationThresholds)


class Settings(BaseModel):
    """Root configuration object aggregating every sub-section."""

    app: AppSettings = Field(default_factory=AppSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    misp: MISPSettings = Field(default_factory=MISPSettings)
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    render_profiles: Dict[str, str] = Field(default_factory=dict)


def _read_yaml(path: Path) -> Dict[str, Any]:
    """Read a YAML file, returning an empty dict when the file is absent."""

    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        # ``safe_load`` returns None for empty files; normalise to a dict.
        return yaml.safe_load(handle) or {}


def _coerce_scalar(value: str) -> Any:
    """Best-effort coercion of an environment string into a scalar.

    Booleans and integers are recognised so that ``PHISHINTEL_MISP__ENABLED=true``
    becomes ``True`` rather than the string ``"true"``. Anything else is left
    as a string and validated later by Pydantic.
    """

    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if value.lstrip("-").isdigit():
        return int(value)
    return value


def _apply_env_overrides(data: Dict[str, Any]) -> Dict[str, Any]:
    """Deep-merge ``PHISHINTEL_``-prefixed environment variables into ``data``.

    ``PHISHINTEL_MISP__URL=https://x`` maps to ``data["misp"]["url"] = "https://x"``.
    This enables secret injection without editing the YAML on disk.
    """

    for env_key, env_value in os.environ.items():
        if not env_key.startswith(_ENV_PREFIX):
            continue
        # Strip prefix and split into nested keys.
        path_parts = env_key[len(_ENV_PREFIX) :].lower().split(_ENV_DELIMITER)
        cursor: Dict[str, Any] = data
        for part in path_parts[:-1]:
            # Walk/create intermediate dicts as needed.
            existing = cursor.get(part)
            if not isinstance(existing, dict):
                existing = {}
                cursor[part] = existing
            cursor = existing
        cursor[path_parts[-1]] = _coerce_scalar(env_value)
    return data


def load_settings(path: str | os.PathLike[str] | None = None) -> Settings:
    """Load and validate platform settings.

    Parameters
    ----------
    path:
        Optional path to a YAML configuration file. When omitted the bundled
        ``config/config.yaml`` shipped with the package is used.

    Returns
    -------
    Settings
        A fully validated settings object.
    """

    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    raw = _read_yaml(config_path)
    merged = _apply_env_overrides(raw)
    # Pydantic performs the final type validation / defaulting.
    return Settings.model_validate(merged)
