"""HTML collector (secondary flow).

Component responsibility
------------------------
Fetch the HTML of a URL *only when the partner did not supply it*. Supports
multiple render profiles (desktop/mobile user agents) so downstream analysis
can compare desktop vs mobile variants, a common phishing cloaking technique.

Execution flow
--------------
``HTMLCollector.collect(url)`` -> HTTP GET with the default profile.
``HTMLCollector.collect_profiles(url, profiles)`` -> one GET per profile,
returning a mapping of profile-name -> HTML.

Safety
------
All network access is wrapped in try/except and honours a timeout; failures
return ``None`` (or skip the profile) rather than raising, so the pipeline can
continue in analysis-only mode.
"""

from __future__ import annotations

from typing import Dict, Optional

import requests

from phishing_intel.logging_config import get_logger

logger = get_logger(__name__)

# Conservative default so a hung server cannot stall the pipeline.
_DEFAULT_TIMEOUT = 15
_DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class HTMLCollector:
    """Fetch HTML documents, optionally across multiple render profiles."""

    def __init__(
        self,
        timeout: int = _DEFAULT_TIMEOUT,
        verify: bool = True,
        session: Optional[requests.Session] = None,
    ) -> None:
        """Create the collector.

        Parameters
        ----------
        timeout:
            Per-request timeout in seconds.
        verify:
            Whether to verify TLS certificates. Phishing infra often uses
            self-signed certs; operators may disable verification for reach.
        session:
            Optional pre-built ``requests.Session`` (injected in tests).
        """

        self.timeout = timeout
        self.verify = verify
        self.session = session or requests.Session()

    def collect(self, url: str, user_agent: str = _DEFAULT_UA) -> Optional[str]:
        """Fetch a single URL with the given user agent.

        Returns the response body as text, or ``None`` on any failure.
        """

        try:
            response = self.session.get(
                url,
                headers={"User-Agent": user_agent},
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=True,
            )
            logger.info("html.collected", url=url, status=response.status_code, bytes=len(response.content))
            return response.text
        except requests.RequestException as exc:
            # Network errors are expected against hostile infra; log and move on.
            logger.warning("html.collect_failed", url=url, error=str(exc))
            return None

    def collect_profiles(
        self, url: str, profiles: Dict[str, str]
    ) -> Dict[str, str]:
        """Fetch a URL once per render profile.

        Parameters
        ----------
        url:
            The target URL.
        profiles:
            Mapping of profile-name -> user-agent string.

        Returns
        -------
        Dict[str, str]
            Mapping of profile-name -> fetched HTML, omitting failed profiles.
        """

        results: Dict[str, str] = {}
        for profile_name, user_agent in profiles.items():
            html = self.collect(url, user_agent=user_agent)
            if html is not None:
                results[profile_name] = html
        logger.info("html.profiles_collected", url=url, profiles=list(results.keys()))
        return results
