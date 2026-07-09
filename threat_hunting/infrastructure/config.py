"""Centralized application settings and dynamic policy loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from threat_hunting.domain.rules import ScoreWeights


class OpsecProfileConfig(BaseModel):
    """OPSEC profile definition for connector transport behavior."""

    name: str
    http_proxy: str | None = None
    https_proxy: str | None = None
    socks5_proxy: str | None = None
    user_agent: str = "threat-hunting-platform/0.1"
    rate_limit_per_minute: int = 60
    retries: int = 3
    backoff_seconds: float = 0.5
    verify_tls: bool = True


class AppSettings(BaseModel):
    """Root settings object for CLI/scheduler/runtime configuration."""

    environment: str = "dev"
    auto_export_threshold: float = 70.0
    score_weights: ScoreWeights = Field(default_factory=ScoreWeights)
    opsec_profiles: dict[str, OpsecProfileConfig] = Field(default_factory=dict)
    enabled_connectors: dict[str, bool] = Field(default_factory=dict)
    dynamic_rules: list[dict[str, Any]] = Field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> "AppSettings":
        """Load settings from YAML file path."""
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        profiles = {
            item["name"]: OpsecProfileConfig(**item)
            for item in raw.get("opsec_profiles", [])
        }
        return cls(
            environment=raw.get("environment", "dev"),
            auto_export_threshold=float(raw.get("auto_export_threshold", 70.0)),
            score_weights=ScoreWeights(**raw.get("score_weights", {})),
            opsec_profiles=profiles,
            enabled_connectors=raw.get("enabled_connectors", {}),
            dynamic_rules=raw.get("dynamic_rules", []),
        )
