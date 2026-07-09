"""
GitHub Connector
================

Searches GitHub for:
    - Code repositories containing sensitive patterns (hardcoded creds, API keys).
    - Gists mentioning monitored keywords or IOCs.
    - Public repository commits leaking credentials or configuration.
    - Issues/discussions mentioning brand names or VIP identities.

Authentication:
    - Requires GITHUB_TOKEN (personal access token or app token).
    - Unauthenticated requests are rate-limited to 10/min; authenticated to 30/min.

Collection strategy:
    - Uses GitHub REST API v3 /search/code and /search/repositories endpoints.
    - Iterates pages up to configured max_pages.
    - Applies keyword queries from the active Keyword list.

Finding metadata:
    - source: SourceType.GITHUB
    - category: Category.CREDENTIAL_LEAK or DATA_BREACH (refined by Detection Engine)
    - source_url: GitHub URL of the file or gist
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.exceptions.domain_exceptions import ConnectorError
from threat_hunting.core.domain.ports.connectors import ConnectorHealthStatus
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)

GITHUB_API = "https://api.github.com"

# Default search queries for credential/secret hunting
DEFAULT_QUERIES = [
    "password leaked",
    "api_key secret",
    "credentials dump",
    '"BEGIN RSA PRIVATE KEY"',
    "DB_PASSWORD",
    "SMTP_PASSWORD",
    ".env leaked",
]


class GitHubConnector(BaseConnector):
    """
    GitHub source connector for code/credential hunting.
    """

    connector_id = "github"
    connector_name = "GitHub Connector"
    source_type = SourceType.GITHUB.value

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._token: str = self._config.get("token", "")
        self._search_queries: list[str] = self._config.get("search_queries", DEFAULT_QUERIES)
        self._max_pages: int = self._config.get("max_pages", 5)

    async def connect(self) -> None:
        """Validate GitHub token and set authorization header."""
        await super().connect()
        if self._token and self._session:
            self._session.headers.update({"Authorization": f"Bearer {self._token}"})
        self._logger.info("github_connected", authenticated=bool(self._token))

    async def collect(self) -> AsyncIterator[dict]:
        """Search GitHub code for each configured query."""
        for query in self._search_queries:
            self._logger.info("github_search", query=query)
            for page in range(1, self._max_pages + 1):
                try:
                    response = await self._get(
                        f"{GITHUB_API}/search/code",
                        params={
                            "q": query,
                            "per_page": 30,
                            "page": page,
                            "sort": "indexed",
                            "order": "desc",
                        },
                        headers={"Accept": "application/vnd.github.v3+json"},
                    )
                    data = response.json()
                    items: list[dict] = data.get("items", [])
                    if not items:
                        break
                    for item in items:
                        item["_query"] = query
                        yield item

                    if len(items) < 30:
                        break

                except Exception as exc:
                    self._logger.warning(
                        "github_search_error",
                        query=query,
                        page=page,
                        error=str(exc),
                    )
                    break

    async def parse(self, raw_item: dict) -> dict:
        """Extract structured data from a GitHub search result item."""
        repo = raw_item.get("repository", {})
        return {
            "id": raw_item.get("sha"),
            "title": f"GitHub: {raw_item.get('name', 'unknown file')} in {repo.get('full_name', 'unknown')}",
            "file_name": raw_item.get("name"),
            "file_path": raw_item.get("path"),
            "repo_name": repo.get("full_name"),
            "repo_description": repo.get("description"),
            "repo_private": repo.get("private", False),
            "html_url": raw_item.get("html_url"),
            "git_url": raw_item.get("git_url"),
            "query": raw_item.get("_query"),
            "owner": repo.get("owner", {}).get("login"),
            "language": repo.get("language"),
            "stars": repo.get("stargazers_count", 0),
            "published_at": datetime.now(timezone.utc),
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed GitHub item into a Finding."""
        return Finding(
            title=parsed_item["title"][:512],
            description=(
                f"Sensitive content detected in GitHub repository "
                f"{parsed_item.get('repo_name', 'unknown')}. "
                f"File: {parsed_item.get('file_path', 'unknown')}. "
                f"Query: {parsed_item.get('query', 'unknown')}"
            )[:4096],
            source=SourceType.GITHUB,
            connector=self.connector_id,
            category=Category.CREDENTIAL_LEAK,
            status=FindingStatus.NORMALIZED,
            source_url=parsed_item.get("html_url"),
            source_id=parsed_item.get("id"),
            source_published_at=parsed_item.get("published_at"),
            raw_data=str(parsed_item),
            normalized_data={
                "platform": "github",
                "repo": parsed_item.get("repo_name"),
                "file_path": parsed_item.get("file_path"),
                "language": parsed_item.get("language"),
                "query": parsed_item.get("query"),
                "owner": parsed_item.get("owner"),
            },
            metadata={
                "stars": parsed_item.get("stars"),
                "is_private": parsed_item.get("repo_private"),
            },
            tags=["github", "code_hunting", "credential_hunting"],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check GitHub API reachability."""
        try:
            start_ms = __import__("time").perf_counter()
            await self._get(f"{GITHUB_API}/rate_limit")
            latency = (__import__("time").perf_counter() - start_ms) * 1000
            return ConnectorHealthStatus(
                healthy=True, message="GitHub API reachable", latency_ms=latency
            )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
