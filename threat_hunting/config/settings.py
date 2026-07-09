"""Configuration loading using Pydantic v2 and YAML."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from threat_hunting.domain.entities import DetectionRule, ScoringPolicy, WatchlistProfile
from threat_hunting.infrastructure.opsec.transport import OPSECProfile


class DatabaseSettings(BaseModel):
    """Database configuration."""

    url: str = "sqlite:///./threat_hunting/data/findings.db"


class ObservabilitySettings(BaseModel):
    """Observability configuration."""

    log_level: str = "INFO"
    otel_endpoint: str | None = None


class AppSettings(BaseModel):
    """Main application runtime settings."""

    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    connectors: dict[str, dict[str, Any]] = Field(default_factory=dict)
    connector_groups: dict[str, list[str]] = Field(default_factory=dict)
    exporters: list[str] = Field(default_factory=lambda: ["json"])
    scheduler_cron: str = "*/30 * * * *"


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handler:
        data = yaml.safe_load(handler) or {}
    if not isinstance(data, dict):
        msg = f"Invalid YAML root in {path}"
        raise ValueError(msg)
    return data


def load_app_settings(config_dir: Path) -> AppSettings:
    """Load app settings from config directory."""
    return AppSettings(**_load_yaml(config_dir / "settings.yml"))


def load_watchlist(config_dir: Path) -> WatchlistProfile:
    """Load watchlist profile from YAML."""
    return WatchlistProfile(**_load_yaml(config_dir / "watchlists.yml"))


def load_detection_rules(config_dir: Path) -> list[DetectionRule]:
    """Load detection rules from YAML."""
    data = _load_yaml(config_dir / "detection_rules.yml")
    raw_rules = data.get("rules", [])
    return [DetectionRule(**rule) for rule in raw_rules]


def load_scoring_policy(config_dir: Path) -> ScoringPolicy:
    """Load scoring policy from YAML."""
    data = _load_yaml(config_dir / "scoring.yml")
    return ScoringPolicy(**data)


def load_opsec_profiles(config_dir: Path) -> dict[str, OPSECProfile]:
    """Load OPSEC profiles from YAML."""
    data = _load_yaml(config_dir / "opsec.yml")
    profiles: dict[str, OPSECProfile] = {}
    for name, profile_data in data.get("profiles", {}).items():
        profiles[name] = OPSECProfile(name=name, **profile_data)
    if "default" not in profiles:
        profiles["default"] = OPSECProfile(name="default")
    return profiles
