"""Typed platform settings.

Responsibility
--------------
Define the whole platform configuration as a validated Pydantic model and load
it from a YAML file with environment-variable overrides. Everything that varies
between deployments (storage backend, export threshold, OPSEC profiles, enabled
connectors, config file locations) lives here as data — never hardcoded.

Precedence: explicit YAML values < environment variables (prefixed ``TH_``).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from threat_hunting.infrastructure.opsec.profile import OpsecProfile
from threat_hunting.infrastructure.scoring.weights import ScoringWeights


class StorageSettings(BaseModel):
    """Which persistence backend to use and its options."""

    backend: str = "sqlite"
    path: str = "data/findings.db"


class ExportSettings(BaseModel):
    """Export defaults and the auto-export-on-threshold policy."""

    default_exporter: str = "json"
    output_dir: str = "exports"
    auto_export_enabled: bool = False
    auto_export_target: str = "misp"
    score_threshold: float = Field(default=70.0, ge=0.0, le=100.0)


class OpsecSettings(BaseModel):
    """OPSEC profiles catalogue and per-connector assignment."""

    offline: bool = True
    profiles: dict[str, OpsecProfile] = Field(default_factory=lambda: {"default": OpsecProfile()})
    connector_profiles: dict[str, str] = Field(default_factory=dict)


class ObservabilitySettings(BaseModel):
    """Logging/metrics/tracing toggles."""

    log_level: str = "INFO"
    json_logs: bool = True
    service_name: str = "threat_hunting"


class Settings(BaseModel):
    """Root settings model for the whole platform."""

    storage: StorageSettings = Field(default_factory=StorageSettings)
    export: ExportSettings = Field(default_factory=ExportSettings)
    opsec: OpsecSettings = Field(default_factory=OpsecSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    scoring: ScoringWeights = Field(default_factory=ScoringWeights)

    connectors_enabled: dict[str, bool] = Field(default_factory=dict)
    detection_regex_rules: dict[str, dict[str, Any]] = Field(default_factory=dict)
    yara_rules: dict[str, str] = Field(default_factory=dict)
    detection_whitelist: list[str] = Field(default_factory=list)
    detection_blacklist: list[str] = Field(default_factory=list)
    detection_min_matches: int = 1

    config_dir: str = "config"
    watchlists_file: str = "config/watchlists.yml"

    def apply_env_overrides(self) -> "Settings":
        """Return a copy with recognised ``TH_*`` environment overrides applied."""
        updates: dict[str, Any] = {}
        if (level := os.environ.get("TH_LOG_LEVEL")) is not None:
            updates["observability"] = self.observability.model_copy(update={"log_level": level})
        if (backend := os.environ.get("TH_STORAGE_BACKEND")) is not None:
            updates["storage"] = self.storage.model_copy(update={"backend": backend})
        if (threshold := os.environ.get("TH_SCORE_THRESHOLD")) is not None:
            try:
                updates["export"] = self.export.model_copy(
                    update={"score_threshold": float(threshold)}
                )
            except ValueError:
                pass
        if (offline := os.environ.get("TH_OPSEC_OFFLINE")) is not None:
            updates["opsec"] = self.opsec.model_copy(
                update={"offline": offline.lower() in {"1", "true", "yes"}}
            )
        return self.model_copy(update=updates) if updates else self


def load_settings(path: str | Path | None = None) -> Settings:
    """Load settings from YAML (if present) with environment overrides applied."""
    if path is None:
        path = os.environ.get("TH_CONFIG", "config/settings.yml")
    path = Path(path)
    if path.exists():
        import yaml

        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        settings = Settings.model_validate(raw)
    else:
        settings = Settings()
    return settings.apply_env_overrides()
