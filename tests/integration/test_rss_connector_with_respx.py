"""Testa o RSS connector end-to-end usando respx (mock httpx)."""

from __future__ import annotations

import httpx
import pytest
import respx

from threat_hunting.infrastructure.config.schemas import OpsecProfile
from threat_hunting.infrastructure.connectors.implementations.rss import RSSConnector
from threat_hunting.infrastructure.opsec.opsec_http_client import OpsecHTTPClient


_RSS_BODY = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item><title>Threat A</title><link>https://ex/a</link><description>d</description></item>
  <item><title>Threat B</title><link>https://ex/b</link><description>d</description></item>
</channel></rss>
"""


@pytest.mark.asyncio
async def test_rss_connector_collects_and_normalizes():
    with respx.mock(assert_all_called=True) as rsx:
        rsx.get("https://feed.example/rss").mock(
            return_value=httpx.Response(200, content=_RSS_BODY.encode("utf-8"))
        )
        profile = OpsecProfile(
            proxy=None,
            timeout_seconds=5,
            retries=0,
            backoff_seconds=0,
            jitter_seconds=0,
            rate_limit_per_second=100,
            user_agents=["test-ua"],
            headers={},
        )
        http = OpsecHTTPClient(profile, name="test")
        connector = RSSConnector(options={"url": "https://feed.example/rss", "max_items": 5}, http=http)
        connector.name = "rss_test"

        items = []
        async for payload in connector.collect():
            items.append(payload)
        assert len(items) == 2
        parsed = await connector.parse(items[0])
        finding = await connector.normalize(parsed)
        assert finding.title == "Threat A"
        assert finding.source.url == "https://ex/a"
        await http.close()
