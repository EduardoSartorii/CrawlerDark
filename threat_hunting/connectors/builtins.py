"""Built-in connector implementations and factories.

These connectors provide production-ready extension points and safe defaults.
Network-heavy sources can be enabled through configuration and OPSEC transport
profiles; in tests or dry runs they can also consume configured seed records.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from bs4 import BeautifulSoup

from threat_hunting.connectors.base import BaseConnector, ConnectorHealth, RawCollectionItem
from threat_hunting.core.domain.entities import Artifact, Finding
from threat_hunting.extractors.patterns import PatternExtractor


class ConfiguredFeedConnector(BaseConnector):
    """Generic connector for configured feeds, APIs, social, and dark web seeds."""

    name = "configured"
    source = "configured"
    category = "osint"
    groups = {"all"}

    def connect(self) -> None:
        """Prepare connector state."""

        self._connected = True

    def collect(self) -> Iterable[RawCollectionItem]:
        """Yield configured items or fetch a configured URL through OPSEC transport."""

        for item in self.config.get("items", []):
            yield dict(item)
        url = self.config.get("url")
        if url and self.transport:
            response = self.transport.request("GET", url)
            text = getattr(response, "text", str(response))
            yield {"title": url, "description": text, "url": url, "raw": text}

    def parse(self, raw: RawCollectionItem) -> RawCollectionItem:
        """Extract readable text from HTML while preserving raw metadata."""

        description = str(raw.get("description") or raw.get("content") or raw.get("raw") or "")
        if "<" in description and ">" in description:
            description = BeautifulSoup(description, "lxml").get_text(" ", strip=True)
        return {**raw, "description": description}

    def extract(self, parsed: RawCollectionItem) -> RawCollectionItem:
        """Attach common IOC and fraud artifacts to parsed data."""

        artifacts, indicators = PatternExtractor().extract(parsed)
        return {**parsed, "artifacts": artifacts, "indicators": indicators}

    def normalize(self, parsed: RawCollectionItem) -> Finding:
        """Create a canonical finding from configured source data."""

        title = str(parsed.get("title") or f"{self.name} observation")
        url = parsed.get("url")
        artifacts = list(parsed.get("artifacts", []))
        if url:
            artifacts.append(Artifact(type="url", value=str(url)))
        return Finding(
            title=title,
            description=str(parsed.get("description") or title),
            source=self.source,
            connector=self.name,
            category=self.category,
            raw_data=dict(parsed),
            normalized_data={"title": title, "description": parsed.get("description"), "url": url},
            metadata={"connector_config": {k: v for k, v in self.config.items() if k != "credentials"}},
            tags=list(parsed.get("tags", [])),
            artifacts=artifacts,
            indicators=list(parsed.get("indicators", [])),
        )

    def health(self) -> ConnectorHealth:
        """Report whether the connector is enabled and configured."""

        return ConnectorHealth(healthy=self.enabled, connector=self.name, details={"source": self.source})

    def close(self) -> None:
        """Close connector state."""

        self._connected = False


class RedditConnector(ConfiguredFeedConnector):
    """Reddit OSINT connector."""

    name = "reddit"
    source = "reddit"
    category = "social"
    groups = {"all", "social", "osint"}


class FacebookConnector(ConfiguredFeedConnector):
    """Facebook brand/social monitoring connector."""

    name = "facebook"
    source = "facebook"
    category = "social"
    groups = {"all", "social", "brand"}


class InstagramConnector(ConfiguredFeedConnector):
    """Instagram brand/social monitoring connector."""

    name = "instagram"
    source = "instagram"
    category = "social"
    groups = {"all", "social", "brand"}


class XConnector(ConfiguredFeedConnector):
    """X/Twitter social monitoring connector."""

    name = "x"
    source = "x"
    category = "social"
    groups = {"all", "social", "osint"}


class TelegramConnector(ConfiguredFeedConnector):
    """Telegram monitoring connector."""

    name = "telegram"
    source = "telegram"
    category = "messaging"
    groups = {"all", "social", "telegram", "osint"}


class DiscordConnector(ConfiguredFeedConnector):
    """Discord monitoring connector."""

    name = "discord"
    source = "discord"
    category = "messaging"
    groups = {"all", "social", "osint"}


class GitHubConnector(ConfiguredFeedConnector):
    """GitHub leak and credential hunting connector."""

    name = "github"
    source = "github"
    category = "code"
    groups = {"all", "code", "osint"}


class GitLabConnector(ConfiguredFeedConnector):
    """GitLab leak and credential hunting connector."""

    name = "gitlab"
    source = "gitlab"
    category = "code"
    groups = {"all", "code", "osint"}


class RSSConnector(ConfiguredFeedConnector):
    """RSS/news/blog feed connector."""

    name = "rss"
    source = "rss"
    category = "news"
    groups = {"all", "feeds", "news", "blogs", "osint"}


class DarkWebConnector(ConfiguredFeedConnector):
    """Dark web monitoring connector through configured OPSEC transport."""

    name = "darkweb"
    source = "darkweb"
    category = "dark_web"
    groups = {"all", "darkweb", "deepweb"}


class MISPConnector(ConfiguredFeedConnector):
    """MISP feed connector."""

    name = "misp"
    source = "misp"
    category = "feed"
    groups = {"all", "feeds", "misp"}


BUILTIN_CONNECTORS = [
    RedditConnector,
    FacebookConnector,
    InstagramConnector,
    XConnector,
    TelegramConnector,
    DiscordConnector,
    GitHubConnector,
    GitLabConnector,
    RSSConnector,
    DarkWebConnector,
    MISPConnector,
]
