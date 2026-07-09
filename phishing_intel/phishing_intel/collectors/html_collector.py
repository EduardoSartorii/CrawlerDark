"""HTML and JavaScript acquisition with evidence-friendly metadata."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup


@dataclass(slots=True)
class HtmlCollectionResult:
    """Collected HTML, inline JavaScript and normalized hashes."""

    url: str
    html: str
    javascript_blobs: list[str]
    html_hash: str
    javascript_hash: str | None


class HtmlCollector:
    """Collector responsible for fallback acquisition when HTML is not provided."""

    def __init__(self, timeout: int = 12, user_agent: str = "Mozilla/5.0 (CTI Analyzer)") -> None:
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def collect(self, url: str) -> HtmlCollectionResult:
        """Fetch HTML from URL and extract inline scripts for analysis."""

        response = requests.get(url, timeout=self.timeout, headers=self.headers)
        response.raise_for_status()
        html = response.text
        scripts = self._extract_inline_scripts(html)
        html_hash = hashlib.sha256(html.encode("utf-8")).hexdigest()
        javascript_hash = self._build_combined_hash(scripts)
        return HtmlCollectionResult(
            url=url,
            html=html,
            javascript_blobs=scripts,
            html_hash=html_hash,
            javascript_hash=javascript_hash,
        )

    @staticmethod
    def _extract_inline_scripts(html: str) -> list[str]:
        """Extract inline JavaScript bodies from script tags."""

        soup = BeautifulSoup(html, "lxml")
        return [script.get_text(strip=True) for script in soup.find_all("script") if script.get_text(strip=True)]

    @staticmethod
    def _build_combined_hash(chunks: list[str]) -> str | None:
        """Generate a deterministic SHA256 hash for script chunks."""

        if not chunks:
            return None
        payload = "\n".join(sorted(chunks))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
