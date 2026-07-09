"""Connector discovery registry.

Built-in factories cover the requested source families. External packages can
register ``threat_hunting.connectors`` entry points that return ``BaseConnector``
subclasses, preserving the plugin contract without modifying the core.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.connectors.generic import HttpConnector, RssConnector, StaticConnector
from threat_hunting.core.domain.entities import ConnectorDefinition
from threat_hunting.infrastructure.config.settings import OpsecProfile
from threat_hunting.infrastructure.opsec.transport import HttpTransportFactory


class ConnectorRegistry:
    """Factory and registry for configured connector instances."""

    def __init__(
        self,
        definitions: list[ConnectorDefinition],
        opsec_profiles: dict[str, OpsecProfile] | None = None,
        transport_factory: HttpTransportFactory | None = None,
    ) -> None:
        self._definitions = definitions
        self._opsec_profiles = opsec_profiles or {"default": OpsecProfile(name="default")}
        self._transport_factory = transport_factory or HttpTransportFactory()
        self._classes: dict[str, type[BaseConnector]] = {
            "static": StaticConnector,
            "http": HttpConnector,
            "rss": RssConnector,
            "reddit": HttpConnector,
            "facebook": HttpConnector,
            "instagram": HttpConnector,
            "x": HttpConnector,
            "telegram": HttpConnector,
            "discord": HttpConnector,
            "github": HttpConnector,
            "gitlab": HttpConnector,
            "blogs": HttpConnector,
            "sites": HttpConnector,
            "paste": HttpConnector,
            "news": RssConnector,
            "darkweb": HttpConnector,
            "deepweb": HttpConnector,
            "forums": HttpConnector,
            "marketplaces": HttpConnector,
            "feeds": RssConnector,
            "api": HttpConnector,
            "misp": HttpConnector,
            "opencti": HttpConnector,
            "threatfox": HttpConnector,
            "greynoise": HttpConnector,
            "virustotal": HttpConnector,
            "abuseipdb": HttpConnector,
            "shodan": HttpConnector,
            "censys": HttpConnector,
            "urlhaus": RssConnector,
            "otx": HttpConnector,
        }

    def discover(self) -> None:
        """Load third-party connector classes from Python entry points."""

        for entry_point in entry_points(group="threat_hunting.connectors"):
            connector_class = entry_point.load()
            self._classes[entry_point.name] = connector_class

    def get(self, name: str) -> BaseConnector:
        """Instantiate a configured connector by name."""

        definition = next((item for item in self._definitions if item.name == name), None)
        if definition is None:
            raise KeyError(f"Connector '{name}' is not configured")
        connector_class = self._classes.get(definition.type)
        if connector_class is None:
            raise KeyError(f"Connector type '{definition.type}' is not registered")
        config: dict[str, Any] = dict(definition.config)
        profile = self._opsec_profiles.get(definition.opsec_profile) or self._opsec_profiles["default"]
        if definition.type not in {"static"}:
            config["transport"] = self._transport_factory.build(profile)
        return connector_class(name=definition.name, source=definition.source, config=config)

    def list(self, enabled_only: bool = True) -> list[ConnectorDefinition]:
        """List configured connector definitions."""

        if enabled_only:
            return [definition for definition in self._definitions if definition.enabled]
        return list(self._definitions)
