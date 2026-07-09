"""Plugin discovery and factory tests."""

from __future__ import annotations

from threat_hunting.infrastructure.container import AppContainer
from threat_hunting.plugins.discovery import build_registry
from threat_hunting.plugins.factory import ConnectorFactory


def test_registry_autodiscovery_exposes_connectors(test_config_path: object) -> None:
    """Ensure autodiscovery registers concrete connector plugins only."""
    container = AppContainer()
    registry = build_registry(container.settings(), container.connector_registry())
    connector_names = registry.names()
    assert "base" not in connector_names
    assert {"reddit", "github", "telegram", "darkweb"}.issubset(set(connector_names))


def test_connector_factory_returns_concrete_connector(test_config_path: object) -> None:
    """Ensure factory creates connector instances from registry."""
    container = AppContainer()
    registry = build_registry(container.settings(), container.connector_registry())
    factory = ConnectorFactory(registry)
    connector = factory.create("reddit")
    assert connector.name == "reddit"
