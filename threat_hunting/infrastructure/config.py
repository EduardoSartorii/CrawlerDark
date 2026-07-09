"""Configuration loader for YAML-driven platform settings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from threat_hunting.core.domain.rules import DetectionRule, ScoringProfile


class OpsecProfile(BaseModel):
    """Network OPSEC profile applied outside connectors."""

    http_proxy: str | None = None
    https_proxy: str | None = None
    socks_proxy: str | None = None
    user_agent: str = "ThreatHuntingCollector/0.1"
    rate_limit_per_minute: int = 60
    retries: int = 3
    backoff_seconds: float = 1.0
    vpn_profile: str | None = None
    credentials_ref: str | None = None


class PlatformSettings(BaseModel):
    """Top-level platform settings."""

    connectors: dict[str, dict[str, Any]] = Field(default_factory=dict)
    opsec_profiles: dict[str, OpsecProfile] = Field(default_factory=lambda: {"default": OpsecProfile()})
    connector_opsec_profiles: dict[str, str] = Field(default_factory=dict)
    detection_rules: list[DetectionRule] = Field(default_factory=list)
    scoring: ScoringProfile = Field(default_factory=ScoringProfile)
    storage: dict[str, Any] = Field(default_factory=lambda: {"backend": "json", "path": "data/findings.json"})
    exporters: dict[str, dict[str, Any]] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    scheduler: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: Path) -> "PlatformSettings":
        """Load settings from YAML."""

        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        return cls.model_validate(data or {})
