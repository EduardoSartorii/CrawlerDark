"""GitHubConnector — busca de código público (API v3)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding
from ....core.domain.value_objects import Category, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


@register_connector("github")
class GitHubConnector(BaseConnector):
    ENDPOINT = "https://api.github.com/search/code"

    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("GitHubConnector requires HTTP client")
        query = str(self.options.get("query", ""))
        token = self.options.get("token")
        max_items = int(self.options.get("max_items", 30))
        if not query or not token:
            return
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
        response = await self.http.get(
            self.ENDPOINT,
            params={"q": query, "per_page": min(max_items, 100)},
            headers=headers,
        )
        data = response.json() or {}
        for item in (data.get("items") or [])[:max_items]:
            yield item

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        repo = (parsed.get("repository") or {}).get("full_name") or "unknown"
        path = parsed.get("path") or ""
        html_url = parsed.get("html_url", "")
        source = SourceRef(source="github", connector=self.name, url=html_url)
        return (
            FindingBuilder()
            .title(f"GitHub hit: {repo}/{path}")
            .description(f"Public GitHub content matched query in {repo}")
            .source(source)
            .category(Category.LEAK)
            .severity(Severity.MEDIUM)
            .raw(parsed)
            .tag("github", "code-search")
            .build()
        )

    async def health(self) -> bool:
        return bool(self.options.get("token")) and bool(self.options.get("query"))
