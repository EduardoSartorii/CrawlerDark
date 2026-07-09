"""Connector blueprint catalog for current and future data sources."""

from __future__ import annotations

from pydantic import BaseModel


class ConnectorBlueprint(BaseModel):
    """Connector metadata used for planning and governance."""

    name: str
    category: str
    requires_auth: bool = False


SUPPORTED_CONNECTOR_BLUEPRINTS: list[ConnectorBlueprint] = [
    ConnectorBlueprint(name="reddit", category="social"),
    ConnectorBlueprint(name="facebook", category="social", requires_auth=True),
    ConnectorBlueprint(name="instagram", category="social", requires_auth=True),
    ConnectorBlueprint(name="x", category="social", requires_auth=True),
    ConnectorBlueprint(name="telegram", category="social"),
    ConnectorBlueprint(name="discord", category="social"),
    ConnectorBlueprint(name="github", category="developer"),
    ConnectorBlueprint(name="gitlab", category="developer"),
    ConnectorBlueprint(name="rss", category="feed"),
    ConnectorBlueprint(name="blogs", category="web"),
    ConnectorBlueprint(name="sites", category="web"),
    ConnectorBlueprint(name="paste-sites", category="leak"),
    ConnectorBlueprint(name="news", category="feed"),
    ConnectorBlueprint(name="darkweb", category="darkweb"),
    ConnectorBlueprint(name="deepweb", category="deepweb"),
    ConnectorBlueprint(name="forums", category="community"),
    ConnectorBlueprint(name="marketplaces", category="darkweb"),
    ConnectorBlueprint(name="feeds", category="feed"),
    ConnectorBlueprint(name="apis", category="api"),
    ConnectorBlueprint(name="misp", category="cti"),
    ConnectorBlueprint(name="opencti", category="cti"),
    ConnectorBlueprint(name="threatfox", category="cti"),
    ConnectorBlueprint(name="greynoise", category="cti"),
    ConnectorBlueprint(name="virustotal", category="cti"),
    ConnectorBlueprint(name="abuseipdb", category="cti"),
    ConnectorBlueprint(name="shodan", category="cti"),
    ConnectorBlueprint(name="censys", category="cti"),
    ConnectorBlueprint(name="urlhaus", category="cti"),
    ConnectorBlueprint(name="alienvault-otx", category="cti"),
]
