"""Configuration loader — centralized YAML settings.

Responsibility
--------------
Load platform settings, OPSEC profiles, scoring and connector configs.
Decoupled from connectors — they only receive OpsecProfile / options.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings

from threat_hunting.core.domain.value_objects import OpsecProfile


class MispSettings(BaseModel):
    url: str | None = None
    key: str | None = None
    auto_export_threshold: float = 75.0


class StorageSettings(BaseModel):
    backend: str = "memory"  # memory | sqlite | postgresql
    database_url: str = "sqlite+aiosqlite:///./data/threat_hunting.db"


class ObservabilitySettings(BaseModel):
    json_logs: bool = False
    log_level: str = "INFO"
    otel_console: bool = False
    metrics_enabled: bool = True


class SchedulerSettings(BaseModel):
    enabled: bool = True
    timezone: str = "UTC"


class PlatformSettings(BaseSettings):
    """Root settings — env overrides via THREAT_HUNTING_ prefix."""

    app_name: str = "Threat Hunting Collection Platform"
    config_dir: str = "config"
    storage: StorageSettings = Field(default_factory=StorageSettings)
    misp: MispSettings = Field(default_factory=MispSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    scheduler: SchedulerSettings = Field(default_factory=SchedulerSettings)
    score_export_threshold: float = 75.0
    enabled_connectors: list[str] = Field(default_factory=list)  # empty = all

    model_config = {"env_prefix": "THREAT_HUNTING_", "env_nested_delimiter": "__"}


def load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def load_settings(config_dir: str | Path = "config") -> PlatformSettings:
    config_dir = Path(config_dir)
    raw = load_yaml(config_dir / "settings.yaml")
    return PlatformSettings(config_dir=str(config_dir), **{k: v for k, v in raw.items() if k != "config_dir"})


def load_opsec_profiles(config_dir: str | Path = "config") -> dict[str, OpsecProfile]:
    raw = load_yaml(Path(config_dir) / "opsec" / "profiles.yaml")
    profiles_raw = raw.get("profiles", {})
    profiles: dict[str, OpsecProfile] = {}
    for name, cfg in profiles_raw.items():
        profiles[name] = OpsecProfile(name=name, **(cfg or {}))
    if "default" not in profiles:
        profiles["default"] = OpsecProfile(name="default")
    return profiles


def load_connector_options(config_dir: str | Path = "config") -> dict[str, dict[str, Any]]:
    connectors_dir = Path(config_dir) / "connectors"
    options: dict[str, dict[str, Any]] = {}
    if not connectors_dir.exists():
        return options
    for path in connectors_dir.glob("*.yaml"):
        data = load_yaml(path)
        name = data.get("name") or path.stem
        options[name] = data.get("options", data)
    return options


__all__ = [
    "PlatformSettings",
    "load_settings",
    "load_opsec_profiles",
    "load_connector_options",
    "load_yaml",
]
