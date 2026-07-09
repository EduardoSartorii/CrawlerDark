"""Connector SDK and registry tests."""

from __future__ import annotations

from threat_hunting.connectors.base import ConnectorHealth
from threat_hunting.connectors.registry import ConnectorRegistry


def test_registry_discovers_builtin_connectors_and_groups() -> None:
    """Registry should discover built-ins and resolve connector groups."""

    registry = ConnectorRegistry().discover()

    assert "github" in registry.names()
    assert {connector.name for connector in registry.resolve("social")} >= {"reddit", "telegram"}


def test_connector_enable_disable_controls_resolution() -> None:
    """Runtime connector state should affect resolution."""

    registry = ConnectorRegistry().discover()

    registry.set_enabled("reddit", False)

    assert all(connector.name != "reddit" for connector in registry.resolve("social"))


def test_builtin_connector_normalizes_to_finding() -> None:
    """Configured connector should emit canonical findings with extracted IOCs."""

    registry = ConnectorRegistry(
        {
            "github": {
                "items": [
                    {
                        "title": "Leak",
                        "description": "Contact admin@acme.test at https://acme.test",
                        "url": "https://github.com/acme/leak",
                    }
                ]
            }
        }
    ).discover()
    connector = registry.create("github")

    connector.connect()
    raw = next(iter(connector.collect()))
    finding = connector.normalize(connector.extract(connector.parse(raw)))
    health = connector.health()
    connector.close()

    assert finding.connector == "github"
    assert "admin@acme.test" in {indicator.value for indicator in finding.indicators}
    assert isinstance(health, ConnectorHealth)
    assert health.healthy is True
