"""Unit tests for connectors, registry, event bus, enrichment and keywords."""

from __future__ import annotations

import pytest

from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.enums import Category, EventName, IndicatorType, SourceType
from threat_hunting.core.domain.events.finding_events import HighSeverityFindingDetected
from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.exceptions import ConnectorDisabledError, ConnectorNotFoundError
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine
from threat_hunting.infrastructure.enrichment.providers import DefangProvider, GeoTagProvider
from threat_hunting.infrastructure.events.bus import InMemoryEventBus
from threat_hunting.infrastructure.keywords.provider import (
    InMemoryKeywordProvider,
    YamlKeywordProvider,
)


def test_registry_discovers_sample_connectors():
    registry = ConnectorRegistry()
    names = {m.name for m in registry.all()}
    assert {"sample_paste", "reddit", "github", "rss", "darkweb", "threatfox"} <= names


def test_registry_get_by_group():
    registry = ConnectorRegistry()
    leak = {c.meta.name for c in registry.by_group("leak")}
    assert "sample_paste" in leak


def test_registry_enable_disable():
    registry = ConnectorRegistry()
    registry.set_enabled("sample_paste", False)
    with pytest.raises(ConnectorDisabledError):
        registry.get("sample_paste")
    registry.set_enabled("sample_paste", True)
    assert registry.get("sample_paste").meta.name == "sample_paste"


def test_registry_unknown_connector():
    with pytest.raises(ConnectorNotFoundError):
        ConnectorRegistry().get("does-not-exist")


def test_sample_connector_collect_parse():
    connector = ConnectorRegistry().get("sample_paste")
    items = list(connector.collect())
    assert len(items) == 4
    finding = connector.parse(items[0])
    assert finding.category is Category.DATA_LEAK
    assert connector.health().healthy


def test_base_connector_requires_meta():
    from threat_hunting.core.domain.entities.raw_item import RawItem
    from threat_hunting.core.domain.exceptions import CollectionError

    class Bad(BaseConnector):
        meta = None

        def collect(self):
            return []

    with pytest.raises(CollectionError):
        Bad().parse(RawItem(connector="x", source="s"))


def test_event_bus_publish_subscribe_and_isolation():
    bus = InMemoryEventBus()
    received = []
    bus.subscribe(EventName.HIGH_SEVERITY_FINDING_DETECTED, lambda e: received.append(e))

    def broken(_e):
        raise ValueError("bad handler")

    bus.subscribe(EventName.HIGH_SEVERITY_FINDING_DETECTED, broken)
    finding = FindingBuilder("t", "c", "s").build()
    bus.publish(HighSeverityFindingDetected(finding=finding, threshold=70))
    assert len(received) == 1
    assert bus.errors  # broken handler captured, not raised


def test_enrichment_geo_and_defang():
    finding = (
        FindingBuilder("t", "c", "s")
        .add_indicator(Indicator(type=IndicatorType.IPV4, value="10.0.0.1"))
        .add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.com"))
        .build()
    )
    EnrichmentEngine([GeoTagProvider(), DefangProvider()]).enrich(finding)
    assert "ip:private" in finding.tags
    assert finding.metadata["defanged"]


def test_yaml_keyword_provider_loads(tmp_path):
    path = tmp_path / "wl.yml"
    path.write_text(
        "watchlists:\n"
        "  - name: b\n"
        "    keywords:\n"
        "      - {term: ACME, type: brand, weight: 20}\n"
        "threat_actors:\n"
        "  - name: LockBit\n"
        "    aliases: [lockbit3]\n",
        encoding="utf-8",
    )
    provider = YamlKeywordProvider(path)
    assert provider.watchlists()[0].name == "b"
    assert provider.threat_actors()[0].name == "LockBit"


def test_in_memory_keyword_provider_filters_disabled():
    from threat_hunting.core.domain.entities.watchlist import Watchlist

    provider = InMemoryKeywordProvider([Watchlist(name="off", enabled=False)])
    assert provider.watchlists() == []
