"""Loader de YAML com resolução de ``${env:VAR}`` (com default opcional).

Uso:
    loader = ConfigLoader("config/")
    settings = loader.load_settings()
    connectors = loader.load_connectors()
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

from .schemas import (
    ConnectorConfig,
    ExporterConfig,
    ScoringConfig,
    Settings,
    WatchlistConfig,
)

_ENV_RE = re.compile(r"\$\{env:([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


def _resolve_env(value: Any) -> Any:
    """Substitui recursivamente placeholders ``${env:VAR}`` em strings."""
    if isinstance(value, str):
        def repl(match: re.Match[str]) -> str:
            var = match.group(1)
            default = match.group(2) or ""
            return os.environ.get(var, default)

        return _ENV_RE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _resolve_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env(v) for v in value]
    return value


class ConfigLoader:
    """Ponto único de entrada para leitura de YAMLs da plataforma."""

    def __init__(self, base_dir: str | Path = "config") -> None:
        self.base_dir = Path(base_dir)

    def _read_yaml(self, name: str) -> dict[str, Any]:
        path = self.base_dir / name
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        return _resolve_env(raw)

    def load_settings(self) -> Settings:
        return Settings.model_validate(self._read_yaml("settings.yaml"))

    def load_connectors(self) -> dict[str, ConnectorConfig]:
        raw = self._read_yaml("connectors.yaml").get("connectors", {})
        return {name: ConnectorConfig.model_validate(cfg) for name, cfg in raw.items()}

    def load_exporters(self) -> dict[str, ExporterConfig]:
        raw = self._read_yaml("exporters.yaml").get("exporters", {})
        return {name: ExporterConfig.model_validate(cfg) for name, cfg in raw.items()}

    def load_scoring(self) -> ScoringConfig:
        return ScoringConfig.model_validate(self._read_yaml("scoring.yaml"))

    def load_watchlists(self) -> WatchlistConfig:
        return WatchlistConfig.model_validate(self._read_yaml("watchlists.yaml"))

    def load_scheduler_jobs(self) -> list[dict[str, Any]]:
        return self._read_yaml("scheduler.yaml").get("jobs", [])

    def load_regex_rules(self, path: str) -> list[dict[str, Any]]:
        full = Path(path) if Path(path).is_absolute() else self.base_dir.parent / path
        if not full.exists():
            return []
        with full.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return data.get("rules", [])
