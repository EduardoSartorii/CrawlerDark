"""
GitHub Connector.

Hunts for sensitive data exposure, credential leaks, and malicious code
published to GitHub repositories and Gists.

Collection Strategy:
    - GitHub Code Search API: searches for keywords in public code
    - GitHub Commit Search: monitors recent commits matching IOC patterns
    - Gist Search: finds pastes containing credentials, tokens, keys
    - Watches specific users/organizations for new repository activity

High-Value Targets:
    - API keys, tokens, passwords in source code
    - Hardcoded credentials (AWS, GCP, Azure, database)
    - Company-specific secrets (internal hostnames, IP ranges)
    - Malware source code publications
    - Stolen code/data being shared publicly
"""

from __future__ import annotations

import json
from typing import Any

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects import ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus


class GitHubConnector(BaseConnector):
    """
    GitHub threat intelligence collector.

    Required config keys:
        token: str — GitHub Personal Access Token (required for code search)
        search_queries: list[str] — code/commit search queries
        organizations: list[str] — orgs to monitor (optional)
        users: list[str] — users to monitor (optional)
        search_type: str — "code", "commits", "gists", "all" (default: "code")
    """

    connector_id = "github"
    source_type = SourceType.GITHUB
    group = "code_repo"
    description = "GitHub secret and threat exposure hunter"
    version = "1.0.0"

    _API_BASE = "https://api.github.com"

    # Default queries targeting credential and secret exposure
    DEFAULT_QUERIES = [
        "password filename:.env",
        "api_key filename:.env",
        "aws_access_key_id",
        "secret_key",
        "private_key BEGIN RSA",
        "token github_pat",
    ]

    async def connect(self) -> None:
        """Verify GitHub token and API access."""
        token = self._config.get("token")
        if not token:
            self.log.warning("github.no_token", note="Rate limited to 10 req/min")
            self._auth_header: dict[str, str] = {}
        else:
            self._auth_header = {"Authorization": f"token {token}"}
            # Verify token
            resp = await self.http.get(
                f"{self._API_BASE}/user",
                headers={**self._auth_header, "Accept": "application/vnd.github.v3+json"},
            )
            if resp.status_code == 200:
                user = resp.json()
                self.log.info("github.authenticated", user=user.get("login"))
            else:
                self.log.warning("github.auth_failed", status=resp.status_code)

    async def collect(self, ctx: CollectionContext) -> None:
        """Execute configured search queries against GitHub."""
        queries = self._config.get("search_queries", self.DEFAULT_QUERIES)
        search_type = self._config.get("search_type", "code")
        limit = ctx.metadata.get("limit", self._config.get("limit", 30))

        per_query_limit = max(1, limit // len(queries)) if queries else limit

        for query in queries:
            try:
                if search_type in ("code", "all"):
                    results = await self._search_code(query, per_query_limit)
                    ctx.raw_items.extend(results)
                if search_type in ("commits", "all"):
                    results = await self._search_commits(query, per_query_limit)
                    ctx.raw_items.extend(results)
            except Exception as exc:
                ctx.errors.append(f"GitHub query '{query}': {exc}")
                self.log.warning("github.query_failed", query=query, error=str(exc))

    async def _search_code(self, query: str, limit: int = 30) -> list[dict[str, Any]]:
        """Search GitHub code."""
        resp = await self.http.get(
            f"{self._API_BASE}/search/code",
            params={"q": query, "per_page": min(limit, 100), "sort": "indexed"},
            headers={
                **self._auth_header,
                "Accept": "application/vnd.github.v3+json",
            },
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for item in data.get("items", []):
            item["_search_query"] = query
            item["_result_type"] = "code"
            results.append(item)
        return results

    async def _search_commits(self, query: str, limit: int = 30) -> list[dict[str, Any]]:
        """Search GitHub commits."""
        resp = await self.http.get(
            f"{self._API_BASE}/search/commits",
            params={"q": query, "per_page": min(limit, 100), "sort": "committer-date"},
            headers={
                **self._auth_header,
                "Accept": "application/vnd.github.cloak-preview+json",
            },
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for item in data.get("items", []):
            item["_search_query"] = query
            item["_result_type"] = "commit"
            results.append(item)
        return results

    async def parse(self, ctx: CollectionContext) -> None:
        """Extract finding-relevant fields from GitHub API results."""
        for item in ctx.raw_items:
            result_type = item.get("_result_type", "code")
            if result_type == "code":
                ctx.parsed_items.append(self._parse_code_result(item))
            elif result_type == "commit":
                ctx.parsed_items.append(self._parse_commit_result(item))

    def _parse_code_result(self, item: dict[str, Any]) -> dict[str, Any]:
        repo = item.get("repository", {})
        return {
            "type": "code",
            "id": item.get("sha", ""),
            "name": item.get("name", ""),
            "path": item.get("path", ""),
            "url": item.get("html_url", ""),
            "repo_name": repo.get("full_name", ""),
            "repo_url": repo.get("html_url", ""),
            "repo_description": repo.get("description", ""),
            "query": item.get("_search_query", ""),
            "stars": repo.get("stargazers_count", 0),
            "language": repo.get("language", ""),
        }

    def _parse_commit_result(self, item: dict[str, Any]) -> dict[str, Any]:
        commit = item.get("commit", {})
        repo = item.get("repository", {})
        return {
            "type": "commit",
            "id": item.get("sha", ""),
            "message": commit.get("message", ""),
            "url": item.get("html_url", ""),
            "repo_name": repo.get("full_name", ""),
            "author": commit.get("author", {}).get("name", ""),
            "date": commit.get("author", {}).get("date", ""),
            "query": item.get("_search_query", ""),
        }

    async def normalize(self, ctx: CollectionContext) -> None:
        """Convert parsed items to Findings."""
        for item in ctx.parsed_items:
            if item["type"] == "code":
                title = f"Exposed secret in {item['repo_name']}: {item['path']}"
                description = (
                    f"Search query: {item['query']}\n"
                    f"File: {item['path']}\n"
                    f"Repository: {item['repo_name']}\n"
                    f"Stars: {item['stars']}"
                )
            else:
                title = f"Suspicious commit in {item['repo_name']}"
                description = (
                    f"Commit message: {item['message'][:500]}\n"
                    f"Author: {item['author']}\n"
                    f"Search query: {item['query']}"
                )

            finding = Finding.create(
                title=title[:512],
                source=f"GitHub: {item['repo_name']}",
                connector=self.connector_id,
                category=self._classify(item),
                source_type=self.source_type,
                description=description,
                raw_data=json.dumps(item),
                tags=["github", item["type"], "code-exposure"],
            )
            finding.source_url = item["url"]
            finding.source_id = item["id"]
            finding.normalized_data = item
            ctx.findings.append(finding)

    def _classify(self, item: dict[str, Any]) -> ThreatCategory:
        query = item.get("query", "").lower()
        if any(w in query for w in ["password", "credential", "token", "api_key", "secret"]):
            return ThreatCategory.CREDENTIAL_LEAK
        if "private_key" in query or "rsa" in query.lower():
            return ThreatCategory.CREDENTIAL_LEAK
        return ThreatCategory.CODE_LEAK

    async def close(self) -> None:
        self._auth_header = {}

    async def health(self) -> ConnectorHealth:
        try:
            resp = await self.http.get(
                f"{self._API_BASE}/rate_limit",
                headers={**self._auth_header, "Accept": "application/vnd.github.v3+json"},
            )
            healthy = resp.status_code == 200
        except Exception as exc:
            return ConnectorHealth(
                connector_id=self.connector_id,
                healthy=False,
                status=ConnectorStatus.ERROR,
                last_error=str(exc),
            )
        return ConnectorHealth(
            connector_id=self.connector_id,
            healthy=healthy,
            status=self._status,
            last_run=self._last_run,
            findings_total=self._total_findings,
        )
