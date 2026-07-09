"""Static JavaScript analyzer for phishing kits.

The analyzer uses conservative regular expressions to identify network APIs,
hardcoded URLs, exposed tokens, and suspicious kit strings without executing
attacker-controlled JavaScript.
"""

from __future__ import annotations

import re

from phishing_intel.models.findings import JavaScriptFinding
from phishing_intel.utils import URL_RE, sha256_text


class JavaScriptAnalyzer:
    """Extract JavaScript network and secret indicators."""

    TOKEN_RE = re.compile(
        r"(?i)(api[_-]?key|token|secret|bearer|authorization)\s*[:=]\s*['\"]([^'\"]{8,})['\"]"
    )
    SUSPICIOUS_RE = re.compile(r"(?i)(telegram|bot|sendmail|smtp|webhook|exfil|credential|otp|ccnum|cvv)")

    def analyze(self, javascript: str) -> JavaScriptFinding:
        """Analyze JavaScript source and return extracted indicators."""

        source = javascript or ""
        hardcoded_urls = sorted(set(URL_RE.findall(source)))
        return JavaScriptFinding(
            fetch_urls=self._call_urls(source, r"fetch\(\s*['\"]([^'\"]+)['\"]"),
            xhr_urls=self._call_urls(source, r"\.open\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"]"),
            axios_urls=self._call_urls(source, r"axios\.(?:get|post|put|request)\(\s*['\"]([^'\"]+)['\"]"),
            jquery_ajax_urls=self._call_urls(source, r"\$\.ajax\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]"),
            hardcoded_urls=hardcoded_urls,
            exposed_tokens=sorted({match.group(2) for match in self.TOKEN_RE.finditer(source)}),
            suspicious_strings=sorted({match.group(1).lower() for match in self.SUSPICIOUS_RE.finditer(source)}),
            external_resources=hardcoded_urls,
            javascript_hash=sha256_text(source),
        )

    def _call_urls(self, source: str, pattern: str) -> list[str]:
        """Return unique URL-like string arguments for a JavaScript API."""

        return sorted(set(re.findall(pattern, source, flags=re.IGNORECASE | re.DOTALL)))
