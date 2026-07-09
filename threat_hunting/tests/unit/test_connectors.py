"""Unit tests for connectors."""

import pytest

from threat_hunting.core.contracts.services import CollectionContext
from threat_hunting.infrastructure.connectors.reddit import RedditConnector
from threat_hunting.infrastructure.connectors.github import GitHubConnector
from threat_hunting.infrastructure.connectors.darkweb import DarkWebConnector
from threat_hunting.infrastructure.connectors.rss import RssConnector
from threat_hunting.infrastructure.connectors.telegram import TelegramConnector
from threat_hunting.infrastructure.plugins.discovery import ConnectorRegistry


@pytest.mark.asyncio
async def test_reddit_connector():
    connector = RedditConnector()
    await connector.connect()
    context = CollectionContext(connector_name="reddit", keywords=["malware"])
    payloads = []
    async for p in connector.collect(context):
        payloads.append(p)
    assert len(payloads) > 0
    parsed = connector.parse(payloads[0])
    draft = connector.normalize(parsed)
    assert draft.connector == "reddit"
    await connector.close()


@pytest.mark.asyncio
async def test_github_connector():
    connector = GitHubConnector()
    await connector.connect()
    context = CollectionContext(connector_name="github", keywords=["api_key"])
    payloads = []
    async for p in connector.collect(context):
        payloads.append(p)
    assert len(payloads) > 0
    await connector.close()


@pytest.mark.asyncio
async def test_darkweb_connector():
    connector = DarkWebConnector()
    await connector.connect()
    context = CollectionContext(connector_name="darkweb", keywords=["leak"])
    count = 0
    async for _ in connector.collect(context):
        count += 1
    assert count > 0
    health = await connector.health()
    assert health.value == "healthy"
    await connector.close()


def test_connector_registry_discovery():
    registry = ConnectorRegistry()
    count = registry.discover()
    assert count > 0
    assert "reddit" in registry.list_names()
    assert "github" in registry.list_names()
    assert "darkweb" in registry.list_names()
