"""Reddit connector.

Responsibility
--------------
Collect recent posts from public subreddit JSON endpoints as raw items. It
demonstrates a network-backed social-media connector: it uses the injected
OPSEC transport (never ``requests``/sockets directly) and degrades gracefully
to an empty result when offline, so the pipeline still runs.
"""

from __future__ import annotations

import json
from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta, HealthStatus
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

_DEFAULT_SUBREDDITS = ("netsec", "cybersecurity")


class RedditConnector(BaseConnector):
    """Collects public Reddit posts via the ``/r/<sub>/new.json`` endpoint."""

    meta = ConnectorMeta(
        name="reddit",
        source=SourceType.SOCIAL_MEDIA,
        category=Category.OSINT,
        description="Public subreddit new-post collector.",
        groups=["social", "osint"],
    )

    def __init__(self, transport=None, subreddits: tuple[str, ...] = _DEFAULT_SUBREDDITS) -> None:
        super().__init__(transport=transport)
        self._subreddits = subreddits

    def collect(self) -> Iterable[RawItem]:
        """Yield the newest posts of each configured subreddit."""
        for sub in self._subreddits:
            url = f"https://www.reddit.com/r/{sub}/new.json?limit=25"
            response = self._transport.get(url)
            if not response.ok:
                continue
            try:
                data = json.loads(response.text)
            except json.JSONDecodeError:
                continue
            for child in data.get("data", {}).get("children", []):
                post = child.get("data", {})
                yield RawItem(
                    connector=self.meta.name,
                    source=f"reddit:/r/{sub}",
                    url="https://www.reddit.com" + post.get("permalink", ""),
                    title=post.get("title", ""),
                    content=post.get("selftext", "") or post.get("title", ""),
                    payload={"author": post.get("author", ""), "subreddit": sub},
                )

    def health(self) -> HealthStatus:
        """Probe Reddit reachability by requesting the first subreddit."""
        url = f"https://www.reddit.com/r/{self._subreddits[0]}/new.json?limit=1"
        response = self._transport.get(url)
        return HealthStatus(
            healthy=response.ok, component=self.meta.name, detail=f"status={response.status_code}"
        )
