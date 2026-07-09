"""Generic production connectors used by configured sources.

The platform ships generic RSS, HTTP and static connectors so new sources can be
enabled through configuration. Specialized connectors can later subclass
``BaseConnector`` and register through entry points without core changes.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from bs4 import BeautifulSoup

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.domain.entities import Finding


class StaticConnector(BaseConnector):
    """Connector for fixtures, local feeds and deterministic tests."""

    def connect(self) -> None:
        self._connected = True

    def collect(self) -> Iterable[Any]:
        return self.config.get("items", [])

    def parse(self, raw_item: Any) -> dict[str, Any]:
        if isinstance(raw_item, dict):
            return raw_item
        return {"title": str(raw_item), "description": str(raw_item), "raw": raw_item}

    def normalize(self, parsed_item: dict[str, Any]) -> Finding:
        title = str(parsed_item.get("title") or parsed_item.get("name") or self.name)
        description = str(parsed_item.get("description") or parsed_item.get("content") or "")
        return Finding(
            title=title,
            description=description,
            source=self.source,
            connector=self.name,
            category=str(parsed_item.get("category", self.config.get("category", "osint"))),
            raw_data=dict(parsed_item),
            normalized_data={
                "title": title,
                "description": description,
                "collected_at": datetime.now(UTC).isoformat(),
            },
            tags=list(parsed_item.get("tags", [])),
        )

    def health(self) -> dict[str, Any]:
        return {"status": "ok", "connector": self.name, "items": len(self.config.get("items", []))}

    def close(self) -> None:
        self._connected = False


class HttpConnector(StaticConnector):
    """HTTP connector that downloads configured URLs through OPSEC transport."""

    def __init__(self, name: str, source: str, config: dict[str, Any] | None = None) -> None:
        super().__init__(name, source, config)
        self.transport = self.config.get("transport")

    def collect(self) -> Iterable[Any]:
        urls = self.config.get("urls", [])
        for url in urls:
            if self.transport is None:
                yield {"title": url, "description": "", "url": url}
                continue
            response = self.transport.get(url)
            yield {"url": url, "body": response.text, "status_code": response.status_code}

    def parse(self, raw_item: Any) -> dict[str, Any]:
        if not isinstance(raw_item, dict) or "body" not in raw_item:
            return super().parse(raw_item)
        soup = BeautifulSoup(raw_item["body"], "lxml")
        title = soup.title.string.strip() if soup.title and soup.title.string else raw_item["url"]
        text = soup.get_text(" ", strip=True)
        return {
            "title": title,
            "description": text[:4000],
            "url": raw_item["url"],
            "status_code": raw_item.get("status_code"),
            "category": self.config.get("category", "site"),
        }

    def close(self) -> None:
        if self.transport is not None:
            self.transport.close()
        super().close()


class RssConnector(HttpConnector):
    """RSS/Atom connector that turns feed entries into findings."""

    def parse(self, raw_item: Any) -> dict[str, Any]:
        if not isinstance(raw_item, dict) or "body" not in raw_item:
            return super().parse(raw_item)
        soup = BeautifulSoup(raw_item["body"], "xml")
        entries = soup.find_all(["item", "entry"])
        return {
            "title": raw_item["url"],
            "description": "RSS feed collected",
            "entries": [
                {
                    "title": (entry.find("title").get_text(strip=True) if entry.find("title") else raw_item["url"]),
                    "description": (
                        entry.find("description").get_text(" ", strip=True)
                        if entry.find("description")
                        else entry.get_text(" ", strip=True)
                    ),
                    "url": entry.find("link").get_text(strip=True) if entry.find("link") else raw_item["url"],
                    "category": self.config.get("category", "news"),
                }
                for entry in entries
            ],
        }

    def normalize(self, parsed_item: dict[str, Any]) -> Finding:
        entries = parsed_item.get("entries") or []
        if entries:
            merged_description = "\n".join(f"{item['title']}: {item['description']}" for item in entries)
            return Finding(
                title=f"{self.name} feed batch",
                description=merged_description[:8000],
                source=self.source,
                connector=self.name,
                category=self.config.get("category", "news"),
                raw_data=parsed_item,
                normalized_data={"entries": entries},
                tags=["rss"],
            )
        return super().normalize(parsed_item)
