"""
Reddit Connector.

Collects threat intelligence signals from Reddit communities.
Targets security-relevant subreddits (r/netsec, r/malware, r/darknet, etc.)
as well as custom watchlist subreddits.

Collection Strategy:
    - Polls new/hot posts from configured subreddits
    - Searches for keyword matches across post titles and bodies
    - Extracts URLs, domains, hashes, and other IOC patterns from content
    - Reddit API v2 (OAuth2) or public JSON API (no auth, rate-limited)

OPSEC:
    - Uses default OPSEC profile (no special proxy needed for public subreddits)
    - Respects Reddit's rate limits (60 req/min authenticated, 10/min public)
"""

from __future__ import annotations

import json
from typing import Any

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects import ThreatCategory
from ...core.domain.value_objects.source_type import SourceType
from .base import BaseConnector, CollectionContext, ConnectorHealth, ConnectorStatus


class RedditConnector(BaseConnector):
    """
    Collects threat intelligence from Reddit.

    Required config keys:
        subreddits: list[str] — target subreddits (without r/)
        keywords: list[str] — filter terms (empty = all posts)
        limit: int — max posts per subreddit (default: 25)
        use_oauth: bool — use OAuth2 API (requires client_id, client_secret)
        client_id: str — Reddit app client ID (optional)
        client_secret: str — Reddit app client secret (optional)
    """

    connector_id = "reddit"
    source_type = SourceType.SOCIAL_MEDIA
    group = "social"
    description = "Reddit threat intelligence collector"
    version = "1.0.0"

    _BASE_URL = "https://www.reddit.com"
    _API_URL = "https://oauth.reddit.com"

    DEFAULT_SUBREDDITS = [
        "netsec",
        "malware",
        "cybersecurity",
        "hacking",
        "darknet",
        "netsec_news",
        "blueteamsec",
    ]

    async def connect(self) -> None:
        """Authenticate with Reddit API if credentials provided."""
        self._access_token: str | None = None
        client_id = self._config.get("client_id")
        client_secret = self._config.get("client_secret")

        if client_id and client_secret:
            await self._authenticate(client_id, client_secret)
            self.log.info("reddit.authenticated")
        else:
            self.log.info("reddit.public_mode", note="Rate limited to 10 req/min")

    async def _authenticate(self, client_id: str, client_secret: str) -> None:
        """OAuth2 authentication via Reddit's token endpoint."""
        response = await self.http.post(
            "https://www.reddit.com/api/v1/access_token",
            data={"grant_type": "client_credentials"},
            headers={
                "Authorization": f"Basic {self._encode_credentials(client_id, client_secret)}",
                "User-Agent": "ThreatHunting/1.0",
            },
        )
        if response.status_code == 200:
            data = response.json()
            self._access_token = data.get("access_token")

    @staticmethod
    def _encode_credentials(client_id: str, client_secret: str) -> str:
        import base64
        credentials = f"{client_id}:{client_secret}"
        return base64.b64encode(credentials.encode()).decode()

    async def collect(self, ctx: CollectionContext) -> None:
        """Fetch posts from configured subreddits."""
        subreddits = self._config.get("subreddits", self.DEFAULT_SUBREDDITS)
        limit = ctx.metadata.get("limit", self._config.get("limit", 25))

        for subreddit in subreddits:
            try:
                posts = await self._fetch_subreddit(subreddit, limit=limit)
                ctx.raw_items.extend(posts)
                self.log.debug("reddit.fetched", subreddit=subreddit, count=len(posts))
            except Exception as exc:
                ctx.errors.append(f"Reddit r/{subreddit}: {exc}")
                self.log.warning("reddit.fetch_failed", subreddit=subreddit, error=str(exc))

    async def _fetch_subreddit(self, subreddit: str, limit: int = 25) -> list[Any]:
        """Fetch posts from a subreddit using public JSON API."""
        url = f"{self._BASE_URL}/r/{subreddit}/new.json"
        params = {"limit": limit, "raw_json": 1}

        response = await self.http.get(url, params=params)
        if response.status_code != 200:
            self.log.warning(
                "reddit.bad_response",
                subreddit=subreddit,
                status=response.status_code,
            )
            return []

        data = response.json()
        posts = data.get("data", {}).get("children", [])
        return [post.get("data", {}) for post in posts]

    async def parse(self, ctx: CollectionContext) -> None:
        """Extract relevant fields from raw Reddit post data."""
        keywords = [k.lower() for k in self._config.get("keywords", [])]

        for post in ctx.raw_items:
            title = post.get("title", "")
            selftext = post.get("selftext", "")
            content = f"{title} {selftext}"

            # Apply keyword filter if configured
            if keywords and not any(kw in content.lower() for kw in keywords):
                continue

            ctx.parsed_items.append({
                "id": post.get("id", ""),
                "title": title,
                "content": selftext,
                "url": f"{self._BASE_URL}{post.get('permalink', '')}",
                "author": post.get("author", "[deleted]"),
                "subreddit": post.get("subreddit", ""),
                "score": post.get("score", 0),
                "num_comments": post.get("num_comments", 0),
                "created_utc": post.get("created_utc", 0),
                "is_self": post.get("is_self", True),
                "external_url": post.get("url", "") if not post.get("is_self") else "",
                "flair": post.get("link_flair_text", ""),
            })

    async def normalize(self, ctx: CollectionContext) -> None:
        """Convert parsed posts into Finding domain objects."""
        for item in ctx.parsed_items:
            title = item["title"]
            if len(title) > 512:
                title = title[:509] + "..."

            finding = Finding.create(
                title=title,
                source=f"Reddit r/{item['subreddit']}",
                connector=self.connector_id,
                category=self._classify_content(item["title"], item["content"]),
                source_type=self.source_type,
                description=item["content"][:2000] if item["content"] else "",
                raw_data=json.dumps(item),
                tags=["reddit", item["subreddit"], "social-media"],
            )
            finding.source_url = item["url"]
            finding.source_id = item["id"]
            finding.normalized_data = {
                "author": item["author"],
                "subreddit": item["subreddit"],
                "upvotes": item["score"],
                "comments": item["num_comments"],
                "external_url": item["external_url"],
            }
            ctx.findings.append(finding)

    def _classify_content(self, title: str, content: str) -> ThreatCategory:
        """Heuristic category classification from post content."""
        text = f"{title} {content}".lower()
        if any(w in text for w in ["credential", "password", "login", "breach", "leak"]):
            return ThreatCategory.CREDENTIAL_LEAK
        if any(w in text for w in ["malware", "ransomware", "trojan", "backdoor", "rat"]):
            return ThreatCategory.MALWARE
        if any(w in text for w in ["phishing", "spam", "scam"]):
            return ThreatCategory.PHISHING
        if any(w in text for w in ["darknet", "dark web", "tor", ".onion"]):
            return ThreatCategory.DARK_WEB
        if any(w in text for w in ["cve-", "vulnerability", "exploit", "rce", "sql injection"]):
            return ThreatCategory.VULNERABILITY
        if any(w in text for w in ["ioc", "indicator", "hash", "ip address", "domain"]):
            return ThreatCategory.IOC
        return ThreatCategory.SOCIAL_MEDIA

    async def close(self) -> None:
        """No persistent connection to close."""
        self._access_token = None

    async def health(self) -> ConnectorHealth:
        """Quick health check via Reddit's public API."""
        try:
            resp = await self.http.get(f"{self._BASE_URL}/r/netsec/new.json?limit=1")
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
