"""Unit tests for connector auto-discovery and the registry factory."""

from __future__ import annotations

from threat_hunting.infrastructure.config.settings import (
    ConnectorSettings,
    PlatformSettings,
)
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry


def _registry(**connectors: ConnectorSettings) -> ConnectorRegistry:
    settings = PlatformSettings(connectors=connectors)
    return ConnectorRegistry(settings=settings).discover()


def test_discovers_builtin_connectors() -> None:
    registry = _registry()
    names = registry.names(include_disabled=True)
    assert {"sample", "rss", "threatfox", "static_file"} <= set(names)


def test_create_returns_configured_instance() -> None:
    registry = _registry()
    connector = registry.create("sample")
    assert isinstance(connector, BaseConnector)
    assert connector.name == "sample"


def test_enable_disable_overrides() -> None:
    registry = _registry(sample=ConnectorSettings(enabled=True))
    assert registry.is_enabled("sample") is True
    registry.disable("sample")
    assert registry.is_enabled("sample") is False
    assert "sample" not in registry.enabled_connectors()
    registry.enable("sample")
    assert registry.is_enabled("sample") is True


def test_config_disabled_connector_excluded() -> None:
    registry = _registry(static_file=ConnectorSettings(enabled=False))
    assert "static_file" not in registry.names()
    assert "static_file" in registry.names(include_disabled=True)
