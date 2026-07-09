"""RSSParser — parser mínimo de feeds RSS/Atom via lxml.

Não depende de feedparser (biblioteca abandonada). Suporta os campos
essenciais: title, link, description, pubDate/updated.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dateutil import parser as date_parser
from lxml import etree


class RSSParser:
    async def parse(self, payload: str | bytes) -> list[dict[str, Any]]:
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        try:
            root = etree.fromstring(payload)
        except etree.XMLSyntaxError:
            return []
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        items: list[dict[str, Any]] = []
        for it in root.iter("item"):
            items.append(self._parse_rss_item(it))
        for it in root.findall(".//atom:entry", ns):
            items.append(self._parse_atom_entry(it, ns))
        return items

    @staticmethod
    def _text(elem: Any) -> str:
        return (elem.text or "").strip() if elem is not None else ""

    @classmethod
    def _parse_rss_item(cls, item: Any) -> dict[str, Any]:
        title = cls._text(item.find("title"))
        link = cls._text(item.find("link"))
        desc = cls._text(item.find("description"))
        pub = cls._text(item.find("pubDate"))
        return {
            "title": title,
            "link": link,
            "description": desc,
            "published_at": cls._parse_date(pub),
        }

    @classmethod
    def _parse_atom_entry(cls, item: Any, ns: dict[str, str]) -> dict[str, Any]:
        title = cls._text(item.find("atom:title", ns))
        link_elem = item.find("atom:link", ns)
        link = link_elem.get("href") if link_elem is not None else ""
        desc = cls._text(item.find("atom:summary", ns))
        pub = cls._text(item.find("atom:updated", ns)) or cls._text(item.find("atom:published", ns))
        return {
            "title": title,
            "link": link,
            "description": desc,
            "published_at": cls._parse_date(pub),
        }

    @staticmethod
    def _parse_date(value: str) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        try:
            dt = date_parser.parse(value)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
