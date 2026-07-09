"""Dark web connector plugin."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.domain.entities import ExecutionContext


class DarkwebConnector(BaseConnector):
    """Collects dark web marketplace and forum references."""

    name = "darkweb"

    def connect(self) -> None:
        self._is_connected = True

    def collect(self, context: ExecutionContext) -> Sequence[dict[str, Any]]:
        if not self._is_connected:
            self.connect()
        return [
            {
                "origin_id": "darkweb-1",
                "title": "Database dump sale announcement",
                "description": "Dump includes vip@acme.com and domain vpn.acme.com allegedly from actor blackowl.",
                "source": "darkweb",
                "category": "leak_hunting",
                "url": "http://hidden.local/listing/1",
                "author": "forum-user-77",
            }
        ]

    def health(self) -> bool:
        return True

    def close(self) -> None:
        self._is_connected = False
