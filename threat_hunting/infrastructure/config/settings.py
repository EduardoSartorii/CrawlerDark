"""Centralized YAML settings.

Connectors receive only typed settings and OPSEC profiles. This prevents source
plugins from owning proxy, retry, credential or threshold policy decisions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from threat_hunting.core.domain.entities import ConnectorDefinition, DetectionRule, ScorePolicy


class OpsecProfile(BaseModel):
    """Network and credential posture for connector execution."""

    name: str
    http_proxy: str | None = None
    https_proxy: str | None = None
    socks_proxy: str | None = None
    user_agent: str = "ThreatHuntingCollection/0.1"
    rate_limit_per_minute: int = 60
    retries: int = 3
    backoff_seconds: float = 1.0
    credential_ref: str | None = None


class ExporterSettings(BaseModel):
    """Runtime settings for an exporter adapter."""

    name: str
    type: str
    enabled: bool = True
    threshold: float = 80.0
    config: dict[str, Any] = Field(default_factory=dict)


class StorageSettings(BaseModel):
    """Persistence backend selection without leaking into business rules."""

    backend: str = "memory"
    url: str | None = None
    path: str = "data/findings.json"
    config: dict[str, Any] = Field(default_factory=dict)


class SchedulerSettings(BaseModel):
    """Scheduler configuration for periodic connector runs."""

    enabled: bool = False
    interval_minutes: int = 60


class AppSettings(BaseModel):
    """Root application settings loaded from YAML."""

    environment: str = "development"
    connectors: list[ConnectorDefinition] = Field(default_factory=list)
    detection_rules: list[DetectionRule] = Field(default_factory=list)
    score_policy: ScorePolicy = Field(default_factory=ScorePolicy)
    opsec_profiles: dict[str, OpsecProfile] = Field(default_factory=dict)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    exporters: list[ExporterSettings] = Field(default_factory=list)
    scheduler: SchedulerSettings = Field(default_factory=SchedulerSettings)
    watchlists: dict[str, list[str]] = Field(default_factory=dict)


def load_settings(path: str | Path = "config/default.yml") -> AppSettings:
    """Load typed application settings from a YAML file."""

    settings_path = Path(path)
    if not settings_path.exists():
        return AppSettings()
    with settings_path.open("r", encoding="utf-8") as stream:
        payload = yaml.safe_load(stream) or {}
    return AppSettings.model_validate(payload)
