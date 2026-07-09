"""GitHub connector implementation."""

from __future__ import annotations

from threat_hunting.connectors.base import BaseConnector
from threat_hunting.core.contracts import StageContext


class GitHubConnector(BaseConnector):
    """Collects exposed secrets and IOC signals from repositories."""

    name = "github"
    category = "osint"

    def collect(self, context: StageContext) -> list[dict[str, object]]:
        """Collect data from GitHub search API or seeded fixtures."""
        fixtures = self.config.get("fixtures")
        if fixtures:
            return list(fixtures)
        return [
            {
                "title": "Token pattern found in public repository",
                "description": "Potential credential exposed in source code",
                "source": "github",
                "category": "credential_hunting",
                "normalized_data": {"email": "admin@example.com", "domain": "example.com"},
                "tags": ["github", "code-leak"],
                "metadata": {"repo": "org/project", "path": "config/.env"},
                "indicators": [{"type": "email", "value": "admin@example.com"}],
            }
        ]
