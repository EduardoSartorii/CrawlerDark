"""
Reddit Connector
================

Collects threat intelligence from configured subreddits using the Reddit API
(via PRAW — Python Reddit API Wrapper).

Collection strategy:
    - Fetches 'new' and 'hot' posts from configured subreddits.
    - Includes post body and top-level comments.
    - Filters posts that mention keywords from the active Keyword list.
    - Rate-limited to 60 requests/minute (Reddit API limit).

Authentication:
    - Requires REDDIT_CLIENT_ID, REDDIT_CLIENT_SECRET, REDDIT_USER_AGENT.
    - Credentials are injected from ConnectorCredentials (never hardcoded).

Finding metadata:
    - source: SourceType.SOCIAL
    - category: Category.SOCIAL_MEDIA (refined by Detection Engine)
    - source_url: full Reddit post URL
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator

import structlog

from threat_hunting.core.domain.entities.finding import Finding, FindingStatus
from threat_hunting.core.domain.exceptions.domain_exceptions import CollectionError, ConnectorError
from threat_hunting.core.domain.ports.connectors import ConnectorHealthStatus
from threat_hunting.core.domain.value_objects.category import Category
from threat_hunting.core.domain.value_objects.source import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

logger = structlog.get_logger(__name__)


class RedditConnector(BaseConnector):
    """
    Reddit source connector.

    Collects posts and comments from threat-intelligence-relevant subreddits.
    """

    connector_id = "reddit"
    connector_name = "Reddit Connector"
    source_type = SourceType.SOCIAL.value

    # Default subreddits relevant to CTI
    DEFAULT_SUBREDDITS = [
        "netsec", "hacking", "cybersecurity", "AskNetsec",
        "blackhat", "Malware", "darknetmarkets",
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._praw_reddit: Any = None
        self._subreddits: list[str] = self._config.get("subreddits", self.DEFAULT_SUBREDDITS)
        self._limit: int = self._config.get("limit", 100)
        self._client_id: str = self._config.get("client_id", "")
        self._client_secret: str = self._config.get("client_secret", "")
        self._user_agent: str = self._config.get("user_agent", "ThreatHuntingBot/1.0")

    async def connect(self) -> None:
        """Authenticate with the Reddit API."""
        if not self._client_id or not self._client_secret:
            raise ConnectorError(
                "Reddit connector requires REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET",
                context={"connector": self.connector_id},
            )
        try:
            import praw  # type: ignore[import-untyped]

            # praw is synchronous; for async use we run it in a thread pool.
            self._praw_reddit = praw.Reddit(
                client_id=self._client_id,
                client_secret=self._client_secret,
                user_agent=self._user_agent,
                check_for_async=False,
            )
        except Exception as exc:
            raise ConnectorError(
                f"Failed to initialize Reddit client: {exc}",
                context={"connector": self.connector_id},
            ) from exc
        await super().connect()

    async def collect(self) -> AsyncIterator[dict]:
        """Yield raw Reddit submissions from configured subreddits."""
        import asyncio

        for subreddit_name in self._subreddits:
            self._logger.info("collecting_subreddit", subreddit=subreddit_name)
            try:
                # Run synchronous PRAW calls in a thread to avoid blocking the event loop.
                def _fetch_new() -> list[dict]:
                    subreddit = self._praw_reddit.subreddit(subreddit_name)
                    items = []
                    for submission in subreddit.new(limit=self._limit):
                        items.append({
                            "id": submission.id,
                            "title": submission.title,
                            "selftext": submission.selftext,
                            "url": submission.url,
                            "permalink": f"https://reddit.com{submission.permalink}",
                            "author": str(submission.author),
                            "score": submission.score,
                            "created_utc": submission.created_utc,
                            "subreddit": subreddit_name,
                            "num_comments": submission.num_comments,
                            "flair": submission.link_flair_text,
                        })
                    return items

                items = await asyncio.get_event_loop().run_in_executor(None, _fetch_new)
                for item in items:
                    yield item
                    await self._throttle()

            except Exception as exc:
                self._logger.warning(
                    "subreddit_collection_error",
                    subreddit=subreddit_name,
                    error=str(exc),
                )

    async def parse(self, raw_item: dict) -> dict:
        """Extract structured fields from a raw Reddit submission dict."""
        content = f"{raw_item.get('title', '')} {raw_item.get('selftext', '')}".strip()
        return {
            "id": raw_item.get("id"),
            "title": raw_item.get("title", "Untitled Reddit Post"),
            "content": content,
            "url": raw_item.get("permalink"),
            "author": raw_item.get("author"),
            "subreddit": raw_item.get("subreddit"),
            "score": raw_item.get("score", 0),
            "published_at": datetime.fromtimestamp(
                raw_item.get("created_utc", 0), tz=timezone.utc
            ),
            "metadata": {
                "num_comments": raw_item.get("num_comments"),
                "flair": raw_item.get("flair"),
                "reddit_score": raw_item.get("score"),
            },
        }

    async def normalize(self, parsed_item: dict) -> Finding:
        """Convert a parsed Reddit item into a Finding."""
        return Finding(
            title=parsed_item["title"][:512],
            description=parsed_item.get("content", "")[:4096],
            source=SourceType.SOCIAL,
            connector=self.connector_id,
            category=Category.SOCIAL_MEDIA,
            status=FindingStatus.NORMALIZED,
            source_url=parsed_item.get("url"),
            source_id=parsed_item.get("id"),
            source_published_at=parsed_item.get("published_at"),
            raw_data=str(parsed_item),
            normalized_data={
                "platform": "reddit",
                "subreddit": parsed_item.get("subreddit"),
                "author": parsed_item.get("author"),
                "reddit_score": parsed_item.get("score"),
            },
            metadata=parsed_item.get("metadata", {}),
            tags=["reddit", f"r/{parsed_item.get('subreddit', 'unknown')}"],
        )

    async def health(self) -> ConnectorHealthStatus:
        """Check Reddit API reachability."""
        try:
            latency = await self._measure_latency("https://www.reddit.com/r/netsec/new.json?limit=1")
            if latency >= 0:
                return ConnectorHealthStatus(
                    healthy=True,
                    message="Reddit API reachable",
                    latency_ms=latency,
                )
        except Exception as exc:
            return ConnectorHealthStatus(healthy=False, message=str(exc))
        return ConnectorHealthStatus(healthy=False, message="Unknown error")
