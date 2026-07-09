"""Teste do RSSParser."""

from __future__ import annotations

import pytest

from threat_hunting.infrastructure.parsers import RSSParser

_RSS_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item>
    <title>Test item</title>
    <link>https://ex.example/a</link>
    <description>desc a</description>
    <pubDate>Tue, 09 Jul 2026 10:00:00 +0000</pubDate>
  </item>
  <item>
    <title>Another</title>
    <link>https://ex.example/b</link>
    <description>desc b</description>
  </item>
</channel></rss>
"""


@pytest.mark.asyncio
async def test_rss_parser_parses_items():
    items = await RSSParser().parse(_RSS_SAMPLE)
    assert len(items) == 2
    assert items[0]["title"] == "Test item"
    assert items[0]["link"] == "https://ex.example/a"
    assert items[0]["published_at"].year == 2026
