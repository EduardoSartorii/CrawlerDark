"""
Platform Settings.

Centralized configuration management using Pydantic Settings.
Settings are loaded from:
    1. Environment variables (highest priority)
    2. .env file
    3. config/config.yaml
    4. Default values (lowest priority)

No secrets in source code. All sensitive values come from environment.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database connection settings."""

    backend: str = Field(default="sqlite", description="sqlite or postgresql")
    url: str = Field(default="sqlite+aiosqlite:///./data/threat_hunting.db")
    pool_size: int = Field(default=5)
    echo: bool = Field(default=False)

    model_config = SettingsConfigDict(env_prefix="DB_")


class RedisSettings(BaseSettings):
    """Redis connection settings (caching, rate limiting)."""

    url: str = Field(default="redis://localhost:6379/0")
    max_connections: int = Field(default=10)

    model_config = SettingsConfigDict(env_prefix="REDIS_")


class MISPSettings(BaseSettings):
    """MISP integration settings."""

    url: str = Field(default="")
    key: str = Field(default="")
    verify_ssl: bool = Field(default=True)
    auto_export_threshold: float = Field(default=7.0)

    model_config = SettingsConfigDict(env_prefix="MISP_")


class OpsecSettings(BaseSettings):
    """OPSEC layer settings."""

    default_proxy: str = Field(default="")
    tor_proxy: str = Field(default="socks5://127.0.0.1:9050")
    requests_per_minute: int = Field(default=30)
    max_retries: int = Field(default=3)

    model_config = SettingsConfigDict(env_prefix="OPSEC_")


class PlatformSettings(BaseSettings):
    """Master platform configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="TH_",
        extra="ignore",
    )

    # Platform
    debug: bool = Field(default=False)
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    json_logs: bool = Field(default=False)
    data_dir: Path = Field(default=Path("./data"))
    config_dir: Path = Field(default=Path("./config"))

    # Metrics
    metrics_enabled: bool = Field(default=True)
    metrics_port: int = Field(default=9090)

    # Collection
    default_collection_limit: int = Field(default=100)
    export_threshold: float = Field(default=7.0)
    dedup_window_hours: int = Field(default=24)
    dedup_similarity_threshold: float = Field(default=0.90)

    # Nested settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    misp: MISPSettings = Field(default_factory=MISPSettings)
    opsec: OpsecSettings = Field(default_factory=OpsecSettings)

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PlatformSettings":
        """Load settings from a YAML config file."""
        path = Path(path)
        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)
        return cls()

    def ensure_data_dir(self) -> None:
        """Create data directory if it doesn't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)


# Module-level singleton (can be overridden in tests)
_settings: PlatformSettings | None = None


def get_settings() -> PlatformSettings:
    """Get the platform settings singleton."""
    global _settings
    if _settings is None:
        _settings = PlatformSettings()
    return _settings


def override_settings(settings: PlatformSettings) -> None:
    """Override settings singleton (for testing)."""
    global _settings
    _settings = settings
