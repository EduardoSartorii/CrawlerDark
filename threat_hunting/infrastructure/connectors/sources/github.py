"""GitHub connector.

Responsibility
--------------
Search public GitHub code/commits for monitored terms (leaked secrets, brand
mentions) via the REST search API. Demonstrates a code-repository connector.
Uses the OPSEC transport and an optional token resolved from the profile.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class GitHubConnector(BaseConnector):
    """Searches public GitHub code for monitored queries."""

    meta = ConnectorMeta(
        name="github",
        source=SourceType.CODE_REPOSITORY,
        category=Category.CREDENTIAL_LEAK,
        description="GitHub code-search collector for leaked secrets/brand mentions.",
        groups=["code", "leak"],
    )

    def __init__(self, transport=None, queries: tuple[str, ...] = ("acme-corp.com",)) -> None:
        super().__init__(transport=transport)
        self._queries = queries

    def collect(self) -> Iterable[RawItem]:
        """Yield code-search hits for each configured query."""
        for query in self._queries:
            url = f"https://api.github.com/search/code?q={query}"
            response = self._transport.get(url, headers={"Accept": "application/vnd.github+json"})
            if not response.ok:
                continue
            try:
                data = json.loads(response.text)
            except json.JSONDecodeError:
                continue
            for item in data.get("items", []):
                repo = item.get("repository", {})
                yield RawItem(
                    connector=self.meta.name,
                    source=f"github:{repo.get('full_name', '')}",
                    url=item.get("html_url", ""),
                    title=f"{repo.get('full_name', '')}:{item.get('path', '')}",
                    content=f"Match for '{query}' in {item.get('path', '')}",
                    payload={"query": query, "repo": repo.get("full_name", "")},
                )
