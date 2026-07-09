"""RedditConnector — via API OAuth pública (client credentials)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from ....core.domain.builders import FindingBuilder
from ....core.domain.entities import Finding
from ....core.domain.value_objects import Category, Severity, SourceRef
from ..base import BaseConnector
from ..registry import register_connector


@register_connector("reddit")
class RedditConnector(BaseConnector):
    TOKEN_URL = "https://www.reddit.com/api/v1/access_token"
    LISTING_URL = "https://oauth.reddit.com/r/{subreddit}/new"

    async def _get_token(self) -> str | None:
        if self.http is None:
            return None
        client_id = self.options.get("client_id")
        client_secret = self.options.get("client_secret")
        if not client_id or not client_secret:
            return None
        auth_header = {"Authorization": self._basic_auth(str(client_id), str(client_secret))}
        r = await self.http.post(
            self.TOKEN_URL,
            data={"grant_type": "client_credentials"},
            headers=auth_header,
        )
        data = r.json() or {}
        return data.get("access_token")

    @staticmethod
    def _basic_auth(user: str, pwd: str) -> str:
        import base64
        raw = f"{user}:{pwd}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    async def collect(self) -> AsyncIterator[dict[str, Any]]:  # type: ignore[override]
        if self.http is None:
            raise RuntimeError("RedditConnector requires HTTP client")
        token = await self._get_token()
        if not token:
            return
        subreddit = str(self.options.get("subreddit", "netsec"))
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": str(self.options.get("user_agent", "threat-hunting/0.1")),
        }
        r = await self.http.get(
            self.LISTING_URL.format(subreddit=subreddit),
            headers=headers,
            params={"limit": 50},
        )
        data = r.json() or {}
        for child in (data.get("data") or {}).get("children") or []:
            yield child.get("data") or {}

    async def parse(self, payload: Any) -> dict[str, Any]:
        return payload if isinstance(payload, dict) else {}

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        title = parsed.get("title", "").strip() or "(reddit post)"
        selftext = parsed.get("selftext", "")
        subreddit = parsed.get("subreddit", "")
        url = "https://www.reddit.com" + (parsed.get("permalink") or "")
        source = SourceRef(source=f"reddit:{subreddit}", connector=self.name, url=url)
        return (
            FindingBuilder()
            .title(title[:400])
            .description(selftext[:2000])
            .source(source)
            .category(Category.SOCIAL)
            .severity(Severity.INFO)
            .raw(parsed)
            .tag("reddit", f"r/{subreddit}")
            .build()
        )

    async def health(self) -> bool:
        return bool(self.options.get("client_id") and self.options.get("client_secret"))
