"""GitHub connector plugin."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.domain.entities import ExecutionContext


class GithubConnector(BaseConnector):
    """Collects leaked secrets and IOC traces from GitHub content."""

    name = "github"

    def connect(self) -> None:
        self._is_connected = True

    def collect(self, context: ExecutionContext) -> Sequence[dict[str, Any]]:
        if not self._is_connected:
            self.connect()
        return [
            {
                "origin_id": "github-1",
                "title": "Potential exposed token in repository",
                "description": "Commit mentions credentials for api.acme.com and acme.com by actor darkspider.",
                "source": "github",
                "category": "leak_hunting",
                "url": "https://github.local/repo/commit/1",
                "author": "scanner-bot",
            }
        ]

    def health(self) -> bool:
        return True

    def close(self) -> None:
        self._is_connected = False
