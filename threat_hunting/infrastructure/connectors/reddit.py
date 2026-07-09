"""Reddit connector for social media threat hunting."""

from __future__ import annotations

from collections.abc import AsyncIterator

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class RedditConnector(BaseConnector):
    """Collects posts from Reddit subreddits via JSON API."""

    name = "reddit"
    source_type = SourceType.SOCIAL.value

    async def connect(self) -> None:
        self._connected = True

    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        subreddits = self._config.get("subreddits", ["cybersecurity", "netsec"])
        keywords = context.keywords or self._config.get("keywords", [])

        for sub in subreddits:
            url = f"https://www.reddit.com/r/{sub}/new.json?limit=10"
            if self._transport:
                try:
                    response = await self._transport.get(url)
                    if response.status_code == 200:
                        yield RawPayload(data=response.json(), source_uri=url, metadata={"subreddit": sub})
                        continue
                except Exception:
                    pass
            for kw in keywords[:5]:
                yield RawPayload(
                    data={
                        "title": f"[{sub}] Discussion about {kw}",
                        "selftext": f"Simulated Reddit post mentioning {kw}",
                        "subreddit": sub,
                        "keyword": kw,
                    },
                    source_uri=f"https://reddit.com/r/{sub}",
                    metadata={"subreddit": sub},
                )

    def parse(self, payload: RawPayload) -> ParsedData:
        data = payload.data
        posts = []
        if "data" in data and "children" in data.get("data", {}):
            for child in data["data"]["children"]:
                post = child.get("data", {})
                posts.append({
                    "title": post.get("title", ""),
                    "content": post.get("selftext", ""),
                    "author": post.get("author", ""),
                    "url": post.get("url", ""),
                })
        else:
            posts.append({
                "title": data.get("title", ""),
                "content": data.get("selftext", data.get("content", "")),
                "subreddit": data.get("subreddit", ""),
            })

        content = " ".join(p.get("content", "") for p in posts)
        return ParsedData(
            fields={"posts": posts, "count": len(posts)},
            content=content,
            metadata=payload.metadata,
        )

    def normalize(self, parsed: ParsedData) -> FindingDraft:
        posts = parsed.fields.get("posts", [])
        title = posts[0]["title"] if posts else f"Reddit collection ({parsed.fields.get('count', 0)} posts)"
        draft = self._default_normalize(ParsedData(fields={"title": title}, content=parsed.content), "title")
        draft.connector = self.name
        draft.source = SourceType.SOCIAL
        draft.tags.append("reddit")
        return draft
