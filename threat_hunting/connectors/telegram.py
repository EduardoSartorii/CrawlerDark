"""Telegram connector plugin."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.domain.entities import ExecutionContext


class TelegramConnector(BaseConnector):
    """Collects threat actor chatter from telegram channels."""

    name = "telegram"

    def connect(self) -> None:
        self._is_connected = True

    def collect(self, context: ExecutionContext) -> Sequence[dict[str, Any]]:
        if not self._is_connected:
            self.connect()
        return [
            {
                "origin_id": "telegram-1",
                "title": "New campaign mention",
                "description": "Campaign references acme.com and wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa.",
                "source": "telegram",
                "category": "campaign_discovery",
                "url": "https://telegram.local/channel/1",
                "author": "intel-channel",
            },
            {
                "origin_id": "telegram-2",
                "title": "Follow-up infrastructure post",
                "description": "Operator published admin@acme.com and acme.com mirror update.",
                "source": "telegram",
                "category": "ioc_hunting",
                "url": "https://telegram.local/channel/2",
                "author": "intel-channel",
            },
        ]

    def health(self) -> bool:
        return True

    def close(self) -> None:
        self._is_connected = False
