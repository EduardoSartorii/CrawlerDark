"""
HTML collector for phishing page acquisition.

Fetches HTML content from suspicious URLs when not provided by CTI partners.
Supports multi-profile rendering via User-Agent rotation.

Architectural Responsibility:
    Secondary collection path - only invoked when HTML is not pre-supplied.
    Primary flow prioritizes partner-provided artifacts.

Flow:
    1. Receive URL and optional render profile
    2. Fetch with appropriate User-Agent
    3. Store raw HTML as evidence
    4. Return content for static analysis
"""

from __future__ import annotations

from typing import Any

import requests
import structlog

from phishing_intel.models.findings import RenderProfile
from phishing_intel.utils import EvidenceStore, sha256_hash

logger = structlog.get_logger(__name__)


class HTMLCollector:
    """
    HTTP-based HTML collector with multi-profile support.

    Implements separation between collection and analysis per OPSEC requirements.
  Evidence is preserved before any analysis begins.
    """

    DEFAULT_HEADERS = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }

    def __init__(
        self,
        config: dict[str, Any],
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        """
        Initialize HTML collector.

        Args:
            config: Platform configuration with collection settings.
            evidence_store: Optional evidence store for artifact preservation.
        """
        self.timeout = config.get("collection", {}).get("timeout", 30)
        self.max_redirects = config.get("collection", {}).get("max_redirects", 5)
        self.user_agents = config.get("collection", {}).get("user_agents", {})
        self.evidence_store = evidence_store
        self.session = requests.Session()

    def _get_user_agent(self, profile: RenderProfile | str) -> str:
        """Resolve User-Agent string for render profile."""
        profile_key = profile.value if isinstance(profile, RenderProfile) else profile
        return self.user_agents.get(
            profile_key,
            self.user_agents.get("desktop_chrome", self.DEFAULT_HEADERS.get("User-Agent", "")),
        )

    def collect(
        self,
        url: str,
        profile: RenderProfile = RenderProfile.DESKTOP_CHROME,
    ) -> dict[str, Any]:
        """
        Fetch HTML content from URL.

        Args:
            url: Target URL to collect.
            profile: Browser render profile for User-Agent.

        Returns:
            Dictionary with html content, hash, status, and metadata.

        Raises:
            requests.RequestException: On network or HTTP errors.
        """
        headers = {**self.DEFAULT_HEADERS, "User-Agent": self._get_user_agent(profile)}

        logger.info("html_collection_start", url=url, profile=str(profile))

        response = self.session.get(
            url,
            headers=headers,
            timeout=self.timeout,
            allow_redirects=True,
        )
        response.raise_for_status()

        html_content = response.text
        content_hash = sha256_hash(html_content)

        result = {
            "url": url,
            "html": html_content,
            "html_hash": content_hash,
            "status_code": response.status_code,
            "final_url": response.url,
            "profile": profile.value if isinstance(profile, RenderProfile) else profile,
            "headers": dict(response.headers),
        }

        # Preserve evidence before analysis
        if self.evidence_store:
            evidence = self.evidence_store.store("html", html_content, url, {"profile": str(profile)})
            result["evidence"] = evidence

        logger.info(
            "html_collection_complete",
            url=url,
            html_hash=content_hash,
            status_code=response.status_code,
        )
        return result

    def collect_multi_profile(self, url: str) -> dict[str, dict[str, Any]]:
        """
        Collect HTML across all render profiles for diff analysis.

        Args:
            url: Target URL.

        Returns:
            Dictionary mapping profile name to collection result.
        """
        results: dict[str, dict[str, Any]] = {}
        for profile in RenderProfile:
            try:
                results[profile.value] = self.collect(url, profile)
            except requests.RequestException as exc:
                logger.warning(
                    "profile_collection_failed",
                    url=url,
                    profile=profile.value,
                    error=str(exc),
                )
                results[profile.value] = {"error": str(exc), "url": url, "profile": profile.value}
        return results
