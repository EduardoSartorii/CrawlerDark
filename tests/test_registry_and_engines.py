"""Connector registry and engine behavior tests."""

from threat_hunting.connectors.generic import StaticConnector
from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.domain.entities import ConnectorDefinition, Finding, ScorePolicy
from threat_hunting.extractors.ioc import RegexIndicatorExtractor
from threat_hunting.scoring.engine import WeightedScoringEngine


def test_registry_instantiates_configured_connector() -> None:
    """The registry factory returns a BaseConnector subclass from configuration."""

    registry = ConnectorRegistry(
        [
            ConnectorDefinition(
                name="github",
                type="static",
                source="github",
                config={"items": [{"title": "Repo leak", "description": "token"}]},
            )
        ]
    )

    connector = registry.get("github")

    assert isinstance(connector, StaticConnector)
    assert connector.health()["status"] == "ok"


def test_extractor_and_scorer_handle_iocs_and_credentials() -> None:
    """IOC extraction feeds the configurable scoring engine."""

    finding = Finding(
        title="Card and email leak",
        description="admin@example.com used card 4111 1111 1111 1111 at example.com",
        source="paste",
        connector="paste",
        category="card_hunting",
    )

    extracted = RegexIndicatorExtractor().extract(finding)
    scored = WeightedScoringEngine(
        ScorePolicy(weights={"email": 2, "card": 8, "domain": 3, "credential": 4})
    ).score(extracted)

    assert {indicator.type.value for indicator in extracted.indicators} >= {"email", "card", "domain"}
    assert scored.score >= 17
