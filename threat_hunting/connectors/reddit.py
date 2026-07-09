"""Reddit connector plugin."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.domain.entities import ExecutionContext


class RedditConnector(BaseConnector):
    """Collects threat-related posts from Reddit-like sources."""

    name = "reddit"

    def connect(self) -> None:
        self._is_connected = True

    def collect(self, context: ExecutionContext) -> Sequence[dict[str, Any]]:
        if not self._is_connected:
            self.connect()
        return [
            {
                "origin_id": "reddit-1",
                "title": "Leaked corporate credentials listed",
                "description": "Actor shared admin@example.com and panel.example.org access.",
                "source": "reddit",
                "category": "credential_hunting",
                "url": "https://reddit.local/post/1",
                "author": "threat-feed",
            }
        ]

    def health(self) -> bool:
        return True

    def close(self) -> None:
        self._is_connected = False
