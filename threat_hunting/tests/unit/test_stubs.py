"""Unit tests for stub connectors and additional connectors."""

import pytest

from threat_hunting.core.contracts.services import CollectionContext
from threat_hunting.infrastructure.connectors.stubs import (
    FacebookConnector, VirusTotalConnector, XConnector,
)
from threat_hunting.infrastructure.connectors.telegram import TelegramConnector
from threat_hunting.infrastructure.connectors.rss import RssConnector
from threat_hunting.infrastructure.connectors.sites import HttpSiteConnector
from threat_hunting.infrastructure.plugins.discovery import ConnectorRegistry


@pytest.mark.asyncio
async def test_stub_connectors():
    for cls in [FacebookConnector, XConnector, VirusTotalConnector]:
        c = cls()
        await c.connect()
        async for p in c.collect(CollectionContext(connector_name=cls.name)):
            parsed = c.parse(p)
            draft = c.normalize(parsed)
            assert draft.connector == cls.name
            break
        await c.close()


@pytest.mark.asyncio
async def test_telegram_connector():
    c = TelegramConnector()
    await c.connect()
    async for p in c.collect(CollectionContext(connector_name="telegram")):
        draft = c.normalize(c.parse(p))
        assert "telegram" in draft.tags
        break
    await c.close()


@pytest.mark.asyncio
async def test_rss_connector():
    c = RssConnector()
    await c.connect()
    async for p in c.collect(CollectionContext(connector_name="rss")):
        draft = c.normalize(c.parse(p))
        assert draft.connector == "rss"
        break
    await c.close()


@pytest.mark.asyncio
async def test_sites_connector():
    c = HttpSiteConnector(config={"urls": []})
    await c.connect()
    async for p in c.collect(CollectionContext(connector_name="sites", keywords=["test"])):
        draft = c.normalize(c.parse(p))
        assert draft.connector == "sites"
        break
    await c.close()


def test_registry_get_not_found():
    registry = ConnectorRegistry()
    with pytest.raises(Exception):
        registry.get("nonexistent")


def test_registry_create_with_config():
    registry = ConnectorRegistry()
    registry.register(FacebookConnector)
    c = registry.create_with_config("facebook")
    assert c.name == "facebook"
