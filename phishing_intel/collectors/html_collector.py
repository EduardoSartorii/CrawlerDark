"""Optional HTML collector for incidents without partner-supplied HTML."""

from __future__ import annotations

from pathlib import Path

import requests

from phishing_intel.utils import preserve_evidence


class HtmlCollector:
    """Fetch HTML only when upstream CTI partners did not provide it."""

    def __init__(self, timeout: int = 15, user_agent: str = "PhishingIntel/0.1") -> None:
        """Create a requests-based HTML collector."""

        self.timeout = timeout
        self.user_agent = user_agent

    def collect(self, url: str) -> str:
        """Fetch raw HTML from a URL using a deterministic user agent."""

        response = requests.get(url, timeout=self.timeout, headers={"User-Agent": self.user_agent})
        response.raise_for_status()
        return response.text

    def collect_and_store(self, url: str, evidence_path: Path, campaign_id: str) -> tuple[str, Path]:
        """Fetch HTML and preserve it as chain-of-evidence material."""

        html = self.collect(url)
        path = preserve_evidence(evidence_path, campaign_id, "raw.html", html)
        return html, path
