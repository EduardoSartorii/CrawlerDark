"""Tests for network-backed connectors using a fake OPSEC transport.

These exercise each connector's collect/parse logic deterministically (no real
network) by injecting a transport that returns canned responses.
"""

from __future__ import annotations

import json

from threat_hunting.core.application.ports.transport import TransportResponse
from threat_hunting.infrastructure.connectors.sources.darkweb import DarkWebConnector
from threat_hunting.infrastructure.connectors.sources.github import GitHubConnector
from threat_hunting.infrastructure.connectors.sources.reddit import RedditConnector
from threat_hunting.infrastructure.connectors.sources.rss import RSSConnector
from threat_hunting.infrastructure.connectors.sources.threatfox import ThreatFoxConnector
from threat_hunting.infrastructure.parsers.html_parser import HtmlTextParser


class _CannedTransport:
    """Transport returning a fixed response body for every request."""

    def __init__(self, text: str, status: int = 200) -> None:
        self._text = text
        self._status = status

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def request(self, method, url, **kwargs):
        return TransportResponse(status_code=self._status, text=self._text, url=url)


def test_reddit_parses_posts():
    body = json.dumps(
        {"data": {"children": [{"data": {"title": "leak", "selftext": "x", "permalink": "/r/x/1", "author": "a", "subreddit": "netsec"}}]}}
    )
    connector = RedditConnector(transport=_CannedTransport(body), subreddits=("netsec",))
    items = list(connector.collect())
    assert items and items[0].title == "leak"
    assert connector.health().healthy


def test_reddit_handles_bad_status():
    connector = RedditConnector(transport=_CannedTransport("", status=503), subreddits=("x",))
    assert list(connector.collect()) == []
    assert not connector.health().healthy


def test_github_parses_hits():
    body = json.dumps(
        {"items": [{"repository": {"full_name": "org/repo"}, "path": "a.py", "html_url": "http://gh/x"}]}
    )
    connector = GitHubConnector(transport=_CannedTransport(body), queries=("acme",))
    items = list(connector.collect())
    assert items and "org/repo" in items[0].title


def test_rss_parses_feed():
    xml = (
        "<rss><channel>"
        "<item><title>News</title><link>http://n/1</link>"
        "<description>desc</description></item>"
        "</channel></rss>"
    )
    connector = RSSConnector(transport=_CannedTransport(xml), feeds=("http://feed",))
    items = list(connector.collect())
    assert items and items[0].title == "News"


def test_threatfox_parses_iocs():
    body = json.dumps(
        {"data": [{"ioc": "1.2.3.4", "threat_type": "botnet_cc", "ioc_type": "ip:port", "reference": "http://ref"}]}
    )
    connector = ThreatFoxConnector(transport=_CannedTransport(body))
    items = list(connector.collect())
    assert items and "1.2.3.4" in items[0].content


def test_darkweb_parses_html():
    html = "<html><head><title>Leak Site</title></head><body>victim data 1.2.3.4</body></html>"
    connector = DarkWebConnector(transport=_CannedTransport(html), onion_urls=("http://x.onion",))
    items = list(connector.collect())
    assert items and items[0].title == "Leak Site"
    assert "victim data" in items[0].content


def test_html_text_parser():
    parser = HtmlTextParser()
    title, text = parser.parse(
        "<html><head><title>T</title><script>var x=1</script></head><body>hello</body></html>"
    )
    assert title == "T"
    assert "hello" in text
    assert "var x" not in text
    assert parser.parse("") == ("", "")
