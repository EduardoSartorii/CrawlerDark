"""
PluginLoader
============

Central plugin management for the Threat Hunting Platform.
Discovers and loads connectors, exporters, rules, and enrichers
from the filesystem and Python entry points.

Usage:
    loader = PluginLoader()
    loader.discover_connectors(registry)
    loader.discover_rules(rule_repo)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry

logger = structlog.get_logger(__name__)


class PluginLoader:
    """Central plugin loader for all extension types."""

    def __init__(self, plugin_dirs: list[Path] | None = None) -> None:
        self._plugin_dirs = plugin_dirs or []

    def discover_connectors(self, registry: "ConnectorRegistry") -> int:
        """Discover and register all connectors from the filesystem."""
        count = registry.discover()
        logger.info("plugins_discovered", type="connector", count=count)
        return count

    def add_plugin_directory(self, path: Path) -> None:
        """Add an external directory to be scanned for plugins."""
        if path.is_dir() and path not in self._plugin_dirs:
            self._plugin_dirs.append(path)

    def load_rules_from_directory(self, rules_dir: Path) -> list[dict]:
        """Load YAML/JSON rule files from the given directory.

        Returns a list of raw rule dicts ready for IRuleRepository.save().
        """
        import yaml
        import json

        rules: list[dict] = []
        if not rules_dir.exists():
            return rules

        for path in rules_dir.rglob("*"):
            if path.suffix not in (".yaml", ".yml", ".json"):
                continue
            try:
                if path.suffix == ".json":
                    with open(path) as f:
                        data = json.load(f)
                else:
                    with open(path) as f:
                        data = yaml.safe_load(f)
                if isinstance(data, dict):
                    rules.append(data)
                elif isinstance(data, list):
                    rules.extend(data)
            except Exception as exc:
                logger.warning("rule_file_load_error", path=str(path), error=str(exc))

        logger.info("rules_loaded_from_directory", count=len(rules), directory=str(rules_dir))
        return rules
