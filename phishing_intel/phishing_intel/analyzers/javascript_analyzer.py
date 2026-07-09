"""Static JavaScript analyzer for exfiltration and IOC extraction."""

from __future__ import annotations

import hashlib
import re

from phishing_intel.models.findings import JavaScriptAnalysisResult


class JavaScriptAnalyzer:
    """Extract exfiltration targets and leaked secrets from JavaScript."""

    FETCH_RE = re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]")
    XHR_RE = re.compile(r"\.open\(\s*['\"][A-Z]+['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    AXIOS_RE = re.compile(r"axios\.(?:post|get|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    JQUERY_RE = re.compile(r"\$\.ajax\(\s*\{[^}]*url\s*:\s*['\"]([^'\"]+)['\"]", re.IGNORECASE | re.DOTALL)
    URL_RE = re.compile(r"https?://[^\s'\"`<>]+", re.IGNORECASE)
    TOKEN_RE = re.compile(r"(?:token|bearer|auth|session)[\"'\s:=]+([a-zA-Z0-9\-_\.]{12,})", re.IGNORECASE)
    KEY_RE = re.compile(r"(?:api[_-]?key|secret|client[_-]?secret)[\"'\s:=]+([a-zA-Z0-9\-_]{8,})", re.IGNORECASE)
    SUSPICIOUS_RE = re.compile(r"(?:telegram|discord|bot token|smtp|mailgun|sendgrid|base64)", re.IGNORECASE)

    def analyze(self, scripts: list[str]) -> JavaScriptAnalysisResult:
        """Analyze JavaScript code blobs and return consolidated findings."""

        merged = "\n".join(scripts)
        fetch_targets = self._extract(self.FETCH_RE, merged)
        xhr_targets = self._extract(self.XHR_RE, merged)
        axios_targets = self._extract(self.AXIOS_RE, merged)
        jquery_ajax_targets = self._extract(self.JQUERY_RE, merged)
        hardcoded_urls = self._extract(self.URL_RE, merged)
        exposed_tokens = self._extract(self.TOKEN_RE, merged)
        exposed_keys = self._extract(self.KEY_RE, merged)
        suspicious_strings = self._extract(self.SUSPICIOUS_RE, merged)
        script_hashes = [hashlib.sha256(blob.encode("utf-8")).hexdigest() for blob in scripts]
        return JavaScriptAnalysisResult(
            fetch_targets=fetch_targets,
            xhr_targets=xhr_targets,
            axios_targets=axios_targets,
            jquery_ajax_targets=jquery_ajax_targets,
            hardcoded_urls=hardcoded_urls,
            exposed_tokens=exposed_tokens,
            exposed_keys=exposed_keys,
            suspicious_strings=suspicious_strings,
            script_hashes=script_hashes,
        )

    @staticmethod
    def _extract(pattern: re.Pattern[str], payload: str) -> list[str]:
        """Extract unique regex matches while preserving deterministic order."""

        seen: set[str] = set()
        extracted: list[str] = []
        for match in pattern.findall(payload):
            normalized = match if isinstance(match, str) else match[0]
            if normalized not in seen:
                seen.add(normalized)
                extracted.append(normalized)
        return extracted
