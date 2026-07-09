"""Platform configuration loaded from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings


class DatabaseConfig(BaseSettings):
    url: str = "sqlite+aiosqlite:///data/threat_hunting.db"
    echo: bool = False


class StorageConfig(BaseSettings):
    backend: str = "sqlite"
    json_path: str = "data/findings"


class OpsecConfig(BaseSettings):
    default_profile: str = "default"
    user_agent: str = "ThreatHuntingPlatform/1.0"
    rate_limit_rps: float = 2.0
    max_retries: int = 3


class ExportConfig(BaseSettings):
    misp_url: str = ""
    misp_api_key: str = ""
    misp_event_id: str = ""
    splunk_hec_url: str = ""
    splunk_token: str = ""
    elastic_url: str = ""
    webhook_url: str = ""
    auto_export_threshold: float = 70.0


class ObservabilityConfig(BaseSettings):
    debug: bool = False
    metrics_port: int = 9090
    tracing_enabled: bool = True


class PlatformConfig(BaseSettings):
    """Central platform configuration."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    opsec: OpsecConfig = Field(default_factory=OpsecConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)
    observability: ObservabilityConfig = Field(default_factory=ObservabilityConfig)
    connectors: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PlatformConfig:
        """Load configuration from YAML file."""
        config_path = Path(path)
        if not config_path.exists():
            return cls()
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return cls(**data)
