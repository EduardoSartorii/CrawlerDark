"""Reddit connector implementation."""

from __future__ import annotations

from typing import Any

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.contracts import StageContext


class RedditConnector(BaseConnector):
    """Collects reddit posts or mocked records for threat hunting."""

    name = "reddit"
    category = "osint"

    def collect(self, context: StageContext) -> list[dict[str, Any]]:
        """Collect data from Reddit API or fallback seed fixtures."""
        fixtures = self.config.get("fixtures")
        if fixtures:
            return list(fixtures)
        keywords = self.config.get("keywords", ["leak", "ransomware"])
        return [
            {
                "title": "Potential leaked credentials in subreddit",
                "description": "User claims to have corporate credentials dump",
                "source": "reddit",
                "category": "credential_hunting",
                "normalized_data": {"keywords": keywords, "ioc": "198.51.100.10"},
                "tags": ["reddit", "osint"],
                "metadata": {"subreddit": "threatintel", "post_id": "abc123"},
                "indicators": [{"type": "ip", "value": "198.51.100.10"}],
            }
        ]
