"""Unit tests for built-in connectors using fake transports (no network)."""

from __future__ import annotations

import json
from collections.abc import Sequence

import pytest

from threat_hunting.core.application.ports.transport import (
    TransportFactoryPort,
    TransportPort,
    TransportResponse,
)
from threat_hunting.core.domain.enums import Category, ConnectorStatus, IndicatorType
from threat_hunting.infrastructure.config.settings import ConnectorSettings
from threat_hunting.infrastructure.connectors.builtins.rss import RSSConnector
from threat_hunting.infrastructure.connectors.builtins.static_file import (
    StaticFileConnector,
)
from threat_hunting.infrastructure.connectors.builtins.threatfox import (
    ThreatFoxConnector,
)


class _FakeTransport(TransportPort):
    """Canned-response transport for deterministic connector tests."""

    def __init__(self, get_text: str = "", post_text: str = "") -> None:
        self.profile = "test"
        self._get_text = get_text
        self._post_text = post_text
        self.closed = False

    async def get(self, url, *, params=None) -> TransportResponse:
        return TransportResponse(status_code=200, text=self._get_text, url=url)

    async def post(self, url, *, data=None, json=None) -> TransportResponse:
        return TransportResponse(status_code=200, text=self._post_text, url=url)

    async def aclose(self) -> None:
        self.closed = True


class _FakeFactory(TransportFactoryPort):
    def __init__(self, transport: _FakeTransport) -> None:
        self._transport = transport

    def for_profile(self, profile: str) -> TransportPort:
        return self._transport


async def test_static_file_connector_reads_files(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("leak dump 8.8.8.8", encoding="utf-8")
    (tmp_path / "b.txt").write_text("another leak", encoding="utf-8")
    connector = StaticFileConnector(
        settings=ConnectorSettings(
            options={"glob": {"dir": str(tmp_path), "pattern": "*.txt"}, "category": "leak_hunting"}
        )
    )
    await connector.connect()
    records = await connector.collect()
    assert len(records) == 2
    assert connector.category is Category.LEAK_HUNTING
    finding = connector.normalize(records[0])
    assert finding.connector == "static_file"


async def test_rss_connector_parses_feed() -> None:
    xml = """<?xml version='1.0'?><rss><channel>
      <item><title>Breach news</title><link>http://n.example/1</link>
        <description>ACME leak dump</description></item>
    </channel></rss>"""
    transport = _FakeTransport(get_text=xml)
    connector = RSSConnector(
        transport_factory=_FakeFactory(transport),
        settings=ConnectorSettings(options={"feeds": ["http://feed.example/rss"]}),
    )
    await connector.connect()
    records = await connector.collect()
    assert len(records) == 1
    assert "Breach news" in records[0].content
    assert records[0].url == "http://n.example/1"
    await connector.close()
    assert transport.closed is True


async def test_threatfox_connector_maps_indicator() -> None:
    payload = {
        "data": [
            {
                "ioc": "1.2.3.4:443",
                "ioc_type": "ip:port",
                "malware_printable": "Cobalt Strike",
                "threat_type": "botnet_cc",
                "reference": "http://ref.example",
                "confidence_level": 90,
            }
        ]
    }
    connector = ThreatFoxConnector(
        transport_factory=_FakeFactory(_FakeTransport(post_text=json.dumps(payload))),
        settings=ConnectorSettings(options={"days": 2}),
    )
    await connector.connect()
    records = await connector.collect()
    assert len(records) == 1
    finding = connector.normalize(records[0])
    assert finding.category is Category.IOC_HUNTING
    assert any(i.type is IndicatorType.IPV4 for i in finding.indicators)
    assert "Cobalt Strike" in finding.tags


async def test_base_connector_transport_guard_and_health() -> None:
    connector = StaticFileConnector(settings=ConnectorSettings(enabled=False))
    with pytest.raises(RuntimeError):
        _ = connector.transport
    assert await connector.health() is ConnectorStatus.DISABLED
