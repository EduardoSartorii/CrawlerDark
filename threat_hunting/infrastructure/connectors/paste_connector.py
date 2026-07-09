"""
Paste Sites Connector.

Monitors paste sites (Pastebin, paste.ee, ghostbin, etc.) for credential dumps,
leaked data, IOCs, and sensitive information.

Paste sites are a common medium for:
    - Credential dumps (username:password lists)
    - Database leak announcements
    - Stolen API keys and tokens
    - Malware C2 configurations
    - PII (emails, CPF, CNPJ, credit cards)
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects import ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus


# Regex patterns for high-value artifact extraction from paste content
_PATTERNS = {
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "ip_v4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+"),
    "bitcoin_wallet": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "api_key_generic": re.compile(r'(?:api[_-]?key|token|secret)["\s:=]+([a-zA-Z0-9\-_]{20,})', re.IGNORECASE),
    "credential_pair": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s\n]+"),
    "cpf": re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    "credit_card": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
}


class PasteSiteConnector(BaseConnector):
    """
    Paste site threat intelligence collector.

    Uses the Pastebin scraping API (requires PRO account) or
    public feeds from paste aggregators.

    Config keys:
        api_key: str — Pastebin API key (required for scraping API)
        keywords: list[str] — filter pastes containing these keywords
        limit: int — max pastes to fetch (default: 50)
        use_scraping_api: bool — use Pastebin scraping API (requires PRO)
    """

    connector_id = "paste_sites"
    source_type = SourceType.PASTE_SITE
    group = "paste"
    description = "Paste site credential and data leak monitor"
    version = "1.0.0"

    _PASTEBIN_SCRAPING = "https://scrape.pastebin.com/api_scraping.php"
    _PASTEBIN_ITEM = "https://scrape.pastebin.com/api_scrape_item.php"

    async def connect(self) -> None:
        self._api_key = self._config.get("api_key", "")
        self.log.info("paste.connected", authenticated=bool(self._api_key))

    async def collect(self, ctx: CollectionContext) -> None:
        """Fetch recent pastes."""
        limit = ctx.metadata.get("limit", self._config.get("limit", 50))
        use_scraping = self._config.get("use_scraping_api", bool(self._api_key))

        try:
            if use_scraping:
                pastes = await self._fetch_scraping_api(limit)
            else:
                # Fallback: public search via paste aggregators
                pastes = await self._fetch_public_feed(limit)

            ctx.raw_items = pastes
            self.log.info("paste.fetched", count=len(pastes))

        except Exception as exc:
            ctx.errors.append(f"Paste collection failed: {exc}")
            self.log.error("paste.collect_failed", error=str(exc))

    async def _fetch_scraping_api(self, limit: int) -> list[dict[str, Any]]:
        """Pastebin scraping API (requires PRO account)."""
        resp = await self.http.get(
            self._PASTEBIN_SCRAPING,
            params={"limit": min(limit, 250)},
        )
        if resp.status_code != 200:
            return []
        return resp.json() if resp.headers.get("content-type", "").startswith("application/json") else []

    async def _fetch_public_feed(self, limit: int) -> list[dict[str, Any]]:
        """Public paste feed via RSS/API aggregators."""
        # Using psbdmp.ws as public paste search
        keywords = self._config.get("keywords", ["password", "credential", "leak"])
        items = []
        for keyword in keywords[:3]:  # Limit to avoid hammering
            resp = await self.http.get(
                "https://psbdmp.ws/api/search",
                params={"q": keyword, "count": limit // len(keywords[:3])},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    items.extend(data.get("data", []))
                except Exception:
                    pass
        return items

    async def parse(self, ctx: CollectionContext) -> None:
        """Extract and classify paste content."""
        keywords = [k.lower() for k in self._config.get("keywords", [])]

        for paste in ctx.raw_items:
            # Handle different paste API response formats
            content = paste.get("content", "") or paste.get("text", "") or ""
            title = paste.get("title", "") or paste.get("name", "Untitled Paste")
            paste_id = paste.get("key", "") or paste.get("id", "")
            url = paste.get("full_url", "") or f"https://pastebin.com/{paste_id}"

            # Apply keyword filter
            combined = f"{title} {content}".lower()
            if keywords and not any(kw in combined for kw in keywords):
                continue

            # Extract artifacts
            artifacts = self._extract_artifacts(content)
            if not artifacts and keywords:
                # Only keep pastes with matches or extracted artifacts
                continue

            ctx.parsed_items.append({
                "id": paste_id,
                "title": title,
                "content": content[:5000],
                "url": url,
                "user": paste.get("user", "anonymous"),
                "date": paste.get("date", ""),
                "expire": paste.get("expire", ""),
                "size": paste.get("size", len(content)),
                "artifacts": artifacts,
            })

    def _extract_artifacts(self, content: str) -> dict[str, list[str]]:
        """Extract IOC-like artifacts from paste content."""
        artifacts: dict[str, list[str]] = {}
        for name, pattern in _PATTERNS.items():
            matches = list(set(pattern.findall(content)))
            if matches:
                artifacts[name] = matches[:50]  # Cap at 50 per type
        return artifacts

    async def normalize(self, ctx: CollectionContext) -> None:
        """Convert pastes to Findings."""
        for item in ctx.parsed_items:
            artifacts = item["artifacts"]
            category = self._classify_artifacts(artifacts)

            # Build summary
            artifact_summary = ", ".join(
                f"{k}: {len(v)}" for k, v in artifacts.items()
            )
            title = f"[Paste] {item['title'][:150]}" if item["title"] != "Untitled Paste" else \
                f"[Paste] {category.value.replace('_', ' ').title()} detected"

            finding = Finding.create(
                title=title,
                source="Paste Sites",
                connector=self.connector_id,
                category=category,
                source_type=self.source_type,
                description=f"Paste content with: {artifact_summary}\n\n{item['content'][:1000]}",
                raw_data=json.dumps({k: v for k, v in item.items() if k != "content"}),
                tags=["paste", "leak"] + list(artifacts.keys())[:5],
            )
            finding.source_url = item["url"]
            finding.source_id = item["id"]
            finding.normalized_data = {"artifact_summary": artifacts, "author": item["user"]}
            ctx.findings.append(finding)

    def _classify_artifacts(self, artifacts: dict[str, list[str]]) -> ThreatCategory:
        if "credential_pair" in artifacts:
            return ThreatCategory.CREDENTIAL_LEAK
        if "credit_card" in artifacts:
            return ThreatCategory.CARD_DATA
        if "cpf" in artifacts:
            return ThreatCategory.CPF_LEAK
        if "api_key_generic" in artifacts:
            return ThreatCategory.CREDENTIAL_LEAK
        if "bitcoin_wallet" in artifacts:
            return ThreatCategory.CRYPTO_THEFT
        if "hash_md5" in artifacts or "hash_sha256" in artifacts:
            return ThreatCategory.IOC
        return ThreatCategory.DATA_LEAK

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
