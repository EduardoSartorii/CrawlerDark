"""
RSS/Blog/News Connector.

Monitors security blogs, news sites, and RSS feeds for threat intelligence.
Acts as a meta-connector — configured with a list of feed URLs to monitor.

Use Cases:
    - Security vendor blog monitoring (Mandiant, CrowdStrike, Recorded Future)
    - CVE/vulnerability news aggregation
    - Threat actor attribution articles
    - Campaign discovery via news coverage
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects import ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus

try:
    from bs4 import BeautifulSoup
    _BS4_AVAILABLE = True
except ImportError:
    _BS4_AVAILABLE = False


_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_MITRE_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


class RSSConnector(BaseConnector):
    """
    RSS/Atom feed threat intelligence collector.

    Config keys:
        feeds: list[dict] — list of feed configs with 'url', 'name', 'category'
        limit_per_feed: int — max items per feed (default: 20)
        keywords: list[str] — filter items containing these keywords (optional)
    """

    connector_id = "rss"
    source_type = SourceType.RSS
    group = "feeds"
    description = "RSS/Atom security blog and news feed collector"
    version = "1.0.0"

    DEFAULT_FEEDS = [
        {"url": "https://feeds.feedburner.com/eset/blog", "name": "ESET Blog", "category": "malware"},
        {"url": "https://www.bleepingcomputer.com/feed/", "name": "BleepingComputer", "category": "news"},
        {"url": "https://krebsonsecurity.com/feed/", "name": "KrebsOnSecurity", "category": "news"},
        {"url": "https://www.darkreading.com/rss.xml", "name": "Dark Reading", "category": "news"},
        {"url": "https://isc.sans.edu/rssfeed_full.xml", "name": "SANS ISC", "category": "ioc"},
    ]

    async def connect(self) -> None:
        self.log.info("rss.connected", feeds=len(self._config.get("feeds", self.DEFAULT_FEEDS)))

    async def collect(self, ctx: CollectionContext) -> None:
        """Fetch all configured RSS feeds."""
        feeds = self._config.get("feeds", self.DEFAULT_FEEDS)
        limit_per_feed = self._config.get("limit_per_feed", 20)

        for feed in feeds:
            try:
                items = await self._fetch_feed(feed["url"], limit_per_feed)
                for item in items:
                    item["_feed_name"] = feed.get("name", feed["url"])
                    item["_feed_category"] = feed.get("category", "general")
                ctx.raw_items.extend(items)
                self.log.debug("rss.feed_fetched", feed=feed.get("name"), items=len(items))
            except Exception as exc:
                ctx.errors.append(f"RSS {feed.get('name', feed['url'])}: {exc}")

    async def _fetch_feed(self, url: str, limit: int) -> list[dict[str, Any]]:
        """Fetch and parse an RSS/Atom feed."""
        resp = await self.http.get(url)
        if resp.status_code != 200:
            return []

        content = resp.text
        items = []

        if _BS4_AVAILABLE:
            soup = BeautifulSoup(content, "xml")
            # Handle both RSS and Atom
            entries = soup.find_all("item") or soup.find_all("entry")
            for entry in entries[:limit]:
                title_tag = entry.find("title")
                link_tag = entry.find("link") or entry.find("url")
                desc_tag = entry.find("description") or entry.find("summary") or entry.find("content")
                date_tag = entry.find("pubDate") or entry.find("published") or entry.find("updated")
                guid_tag = entry.find("guid") or entry.find("id")

                items.append({
                    "title": title_tag.get_text(strip=True) if title_tag else "",
                    "url": (link_tag.get_text(strip=True) if link_tag else ""),
                    "description": (desc_tag.get_text(strip=True)[:2000] if desc_tag else ""),
                    "published": (date_tag.get_text(strip=True) if date_tag else ""),
                    "guid": (guid_tag.get_text(strip=True) if guid_tag else ""),
                })

        return items

    async def parse(self, ctx: CollectionContext) -> None:
        """Filter and enrich feed items."""
        keywords = [k.lower() for k in self._config.get("keywords", [])]

        for item in ctx.raw_items:
            combined = f"{item.get('title', '')} {item.get('description', '')}".lower()
            if keywords and not any(kw in combined for kw in keywords):
                continue

            cves = _CVE_PATTERN.findall(combined)
            mitre_ids = _MITRE_PATTERN.findall(combined)

            ctx.parsed_items.append({
                **item,
                "cves": list(set(cves)),
                "mitre_ids": list(set(mitre_ids)),
            })

    async def normalize(self, ctx: CollectionContext) -> None:
        """Convert feed items to Findings."""
        for item in ctx.parsed_items:
            title = item.get("title", "")[:512] or "Untitled Article"
            feed_name = item.get("_feed_name", "RSS Feed")
            category_hint = item.get("_feed_category", "general")

            finding = Finding.create(
                title=title,
                source=feed_name,
                connector=self.connector_id,
                category=self._classify(item, category_hint),
                source_type=self.source_type,
                description=item.get("description", "")[:2000],
                raw_data=json.dumps(item),
                tags=["rss", "news", category_hint],
            )
            finding.source_url = item.get("url", "")
            finding.source_id = item.get("guid", "")
            finding.normalized_data = {
                "cves": item.get("cves", []),
                "mitre_ids": item.get("mitre_ids", []),
                "published": item.get("published", ""),
                "feed": feed_name,
            }
            if item.get("cves"):
                finding.add_tag("cve")
                for cve in item["cves"]:
                    finding.add_tag(cve.lower())

            ctx.findings.append(finding)

    def _classify(self, item: dict[str, Any], hint: str) -> ThreatCategory:
        if item.get("cves"):
            return ThreatCategory.VULNERABILITY
        text = f"{item.get('title', '')} {item.get('description', '')}".lower()
        if "ransomware" in text:
            return ThreatCategory.RANSOMWARE
        if any(w in text for w in ["credential", "password", "leak", "breach"]):
            return ThreatCategory.CREDENTIAL_LEAK
        if any(w in text for w in ["malware", "trojan", "backdoor"]):
            return ThreatCategory.MALWARE
        if any(w in text for w in ["phishing", "scam"]):
            return ThreatCategory.PHISHING
        return ThreatCategory.NEWS

    async def close(self) -> None:
        pass

    async def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            connector_id=self.connector_id,
            healthy=True,
            status=self._status,
            last_run=self._last_run,
            findings_total=self._total_findings,
        )
