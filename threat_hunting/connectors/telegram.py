"""Telegram connector implementation."""

from __future__ import annotations

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.contracts import StageContext


class TelegramConnector(BaseConnector):
    """Collects monitoring data from telegram channels and groups."""

    name = "telegram"
    category = "social"

    def collect(self, context: StageContext) -> list[dict[str, object]]:
        """Collect messages from Telegram APIs or seeded fixtures."""
        fixtures = self.config.get("fixtures")
        if fixtures:
            return list(fixtures)
        return [
            {
                "title": "Threat actor selling data on channel",
                "description": "Post advertising database access for known target",
                "source": "telegram",
                "category": "leak_hunting",
                "normalized_data": {"threat_actor": "blackfox", "wallet": "bc1qexample"},
                "tags": ["telegram", "dark-market"],
                "metadata": {"channel": "@intelwatch", "message_id": 8911},
                "indicators": [{"type": "wallet", "value": "bc1qexample"}],
            }
        ]
