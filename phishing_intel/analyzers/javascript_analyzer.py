"""
JavaScript static analyzer for phishing pages.

Extracts network calls, hardcoded URLs, exposed credentials,
and suspicious patterns from inline and external JavaScript.

Architectural Responsibility:
    Identifies exfiltration endpoints and kit-specific JavaScript
    patterns without executing code (safe static analysis).
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from phishing_intel.models.findings import JavaScriptFinding
from phishing_intel.utils import sha256_hash

logger = structlog.get_logger(__name__)


class JavaScriptAnalyzer:
    """
    Static JavaScript analysis engine.

    Uses regex-based pattern matching to extract network indicators
    and credential exposure without dynamic execution.
    """

    # Network call patterns
    FETCH_PATTERN = re.compile(
        r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", re.IGNORECASE
    )
    XHR_PATTERN = re.compile(
        r"""\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE)['"`]\s*,\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    JQUERY_AJAX_PATTERN = re.compile(
        r"""\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE | re.DOTALL,
    )
    AXIOS_PATTERN = re.compile(
        r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )

    # URL extraction
    URL_PATTERN = re.compile(
        r"""https?://[^\s'"`<>\)]+""", re.IGNORECASE
    )

    # Credential/token patterns
    TOKEN_PATTERN = re.compile(
        r"""(?:token|api_key|apikey|secret|auth)\s*[=:]\s*['"`]([a-zA-Z0-9_\-\.]{8,})['"`]""",
        re.IGNORECASE,
    )
    KEY_PATTERN = re.compile(
        r"""(?:key|password|passwd|pwd)\s*[=:]\s*['"`]([^'"`]{4,})['"`]""",
        re.IGNORECASE,
    )

    # Suspicious strings common in phishing kits
    SUSPICIOUS_PATTERNS = [
        re.compile(p, re.IGNORECASE)
        for p in [
            r"document\.cookie",
            r"localStorage\.setItem",
            r"sessionStorage",
            r"navigator\.sendBeacon",
            r"atob\s*\(",
            r"btoa\s*\(",
            r"eval\s*\(",
            r"telegram\.org/bot",
            r"api\.telegram",
            r"discord\.com/api/webhooks",
            r"mail\.google\.com/mail",
            r"FormData",
            r"XMLHttpRequest",
        ]
    ]

    def analyze(self, javascript: str, inline_scripts: list[str] | None = None) -> JavaScriptFinding:
        """
        Perform static JavaScript analysis.

        Args:
            javascript: Primary JavaScript content.
            inline_scripts: Additional inline script contents from DOM.

        Returns:
            JavaScriptFinding with extracted indicators.
        """
        # Combine all script sources
        all_js = javascript
        if inline_scripts:
            all_js += "\n".join(inline_scripts)

        logger.info("javascript_analysis_start", js_length=len(all_js))

        finding = JavaScriptFinding(
            fetch_calls=self._extract_unique(self.FETCH_PATTERN, all_js),
            xhr_urls=self._extract_unique(self.XHR_PATTERN, all_js),
            ajax_urls=self._extract_unique(self.JQUERY_AJAX_PATTERN, all_js),
            axios_urls=self._extract_unique(self.AXIOS_PATTERN, all_js),
            hardcoded_urls=self._extract_urls(all_js),
            exposed_tokens=self._extract_unique(self.TOKEN_PATTERN, all_js),
            exposed_keys=self._extract_unique(self.KEY_PATTERN, all_js),
            suspicious_strings=self._find_suspicious(all_js),
            script_hash=sha256_hash(all_js),
        )

        # External resources from hardcoded URLs
        finding.external_resources = [
            u for u in finding.hardcoded_urls if u.startswith("http")
        ]

        logger.info(
            "javascript_analysis_complete",
            fetch_calls=len(finding.fetch_calls),
            hardcoded_urls=len(finding.hardcoded_urls),
            script_hash=finding.script_hash,
        )
        return finding

    def _extract_unique(self, pattern: re.Pattern[str], text: str) -> list[str]:
        """Extract unique matches from regex pattern."""
        return list(dict.fromkeys(pattern.findall(text)))

    def _extract_urls(self, text: str) -> list[str]:
        """Extract all HTTP/HTTPS URLs from JavaScript."""
        urls = self.URL_PATTERN.findall(text)
        return list(dict.fromkeys(urls))

    def _find_suspicious(self, text: str) -> list[str]:
        """Identify suspicious JavaScript patterns."""
        found: list[str] = []
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.search(text):
                found.append(pattern.pattern)
        return found
