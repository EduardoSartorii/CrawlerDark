"""JavaScript analyzer.

Component responsibility
------------------------
Statically analyse JavaScript (inline + external file contents supplied by the
partner) to surface network calls, hardcoded URLs, exposed secrets and
suspicious strings. Emits a
:class:`~phishing_intel.models.findings.JavaScriptAnalysis`.

Execution flow
--------------
``JavaScriptAnalyzer.analyze(scripts)`` -> concatenate scripts -> run each
family of regexes -> deduplicate -> return findings. No code is executed; this
is purely lexical/pattern analysis (safe against malicious payloads).
"""

from __future__ import annotations

import re
from typing import List

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import JavaScriptAnalysis
from phishing_intel.utils import dedupe_preserve_order, extract_urls

logger = get_logger(__name__)

# --- Network-call extraction patterns --------------------------------------
# ``fetch("...")`` / ``fetch('...')`` - capture the first string argument.
_FETCH_RE = re.compile(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", re.I)

# ``xhr.open("POST", "...")`` - capture the URL (second argument).
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`]+)['"`]""", re.I
)

# Detect XMLHttpRequest instantiation even without a captured URL.
_XHR_NEW_RE = re.compile(r"new\s+XMLHttpRequest", re.I)

# ``axios.post("...")`` / ``axios({url:"..."})`` / ``axios("...")``.
_AXIOS_METHOD_RE = re.compile(
    r"""axios\s*(?:\.\s*(?:get|post|put|patch|delete))?\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.I,
)
_AXIOS_CONFIG_RE = re.compile(
    r"""axios\s*\(\s*\{[^}]*?url\s*:\s*['"`]([^'"`]+)['"`]""", re.I | re.S
)

# ``$.ajax({url:"..."})`` / ``jQuery.post("...")`` / ``$.post("...")``.
_JQUERY_AJAX_URL_RE = re.compile(
    r"""(?:\$|jQuery)\s*\.\s*ajax\s*\(\s*\{[^}]*?url\s*:\s*['"`]([^'"`]+)['"`]""",
    re.I | re.S,
)
_JQUERY_SHORTHAND_RE = re.compile(
    r"""(?:\$|jQuery)\s*\.\s*(?:post|get|getJSON|load)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.I,
)

# --- Secret / token exposure patterns --------------------------------------
# Long opaque tokens assigned to token-ish identifiers.
_TOKEN_RE = re.compile(
    r"""(?:token|auth|bearer|secret|session|apikey|api_key)\s*[:=]\s*['"`]([A-Za-z0-9._\-]{12,})['"`]""",
    re.I,
)
# Provider-style API keys (AWS, Google, generic sk_/pk_ prefixes).
_KEY_RE = re.compile(
    r"""\b(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|sk_(?:live|test)_[0-9A-Za-z]{16,}|pk_(?:live|test)_[0-9A-Za-z]{16,})\b"""
)

# --- Suspicious construct patterns -----------------------------------------
# Obfuscation / anti-analysis / data-collection constructs commonly seen in
# phishing kits. Each contributes a "suspicious string" finding.
_SUSPICIOUS_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\batob\s*\(", re.I),
    re.compile(r"\bunescape\s*\(", re.I),
    re.compile(r"\bdocument\.cookie\b", re.I),
    re.compile(r"\bnavigator\.sendBeacon\s*\(", re.I),
    re.compile(r"\bwindow\.location\s*=", re.I),
    re.compile(r"\bFormData\s*\(", re.I),
    re.compile(r"\baddEventListener\s*\(\s*['\"]submit['\"]", re.I),
    re.compile(r"\btelegram\b", re.I),
    re.compile(r"\bbot[0-9]+:[A-Za-z0-9_\-]+\b"),  # Telegram bot token shape
]


class JavaScriptAnalyzer:
    """Static, execution-free JavaScript analyzer."""

    def analyze(self, scripts: List[str]) -> JavaScriptAnalysis:
        """Analyse a collection of JavaScript blobs.

        Parameters
        ----------
        scripts:
            Inline script bodies and/or external file contents.

        Returns
        -------
        JavaScriptAnalysis
        """

        blob = "\n".join(s for s in scripts if s)

        fetch_calls = self._find_all(_FETCH_RE, blob)
        xhr_calls = self._find_all(_XHR_OPEN_RE, blob)
        # Record a marker when XHR is used but the URL is built dynamically.
        if _XHR_NEW_RE.search(blob) and not xhr_calls:
            xhr_calls.append("XMLHttpRequest (dynamic URL)")

        axios_calls = self._find_all(_AXIOS_METHOD_RE, blob) + self._find_all(
            _AXIOS_CONFIG_RE, blob
        )
        jquery_calls = self._find_all(_JQUERY_AJAX_URL_RE, blob) + self._find_all(
            _JQUERY_SHORTHAND_RE, blob
        )

        hardcoded_urls = extract_urls(blob)

        exposed_tokens = self._find_all(_TOKEN_RE, blob)
        exposed_keys = self._find_all(_KEY_RE, blob)

        suspicious: List[str] = []
        for pattern in _SUSPICIOUS_PATTERNS:
            match = pattern.search(blob)
            if match:
                suspicious.append(match.group(0))

        # External resources = the union of every extracted URL/endpoint.
        external_resources = dedupe_preserve_order(
            hardcoded_urls + fetch_calls + axios_calls + jquery_calls
        )

        analysis = JavaScriptAnalysis(
            fetch_calls=dedupe_preserve_order(fetch_calls),
            xhr_calls=dedupe_preserve_order(xhr_calls),
            axios_calls=dedupe_preserve_order(axios_calls),
            jquery_ajax_calls=dedupe_preserve_order(jquery_calls),
            hardcoded_urls=dedupe_preserve_order(hardcoded_urls),
            exposed_tokens=dedupe_preserve_order(exposed_tokens),
            exposed_keys=dedupe_preserve_order(exposed_keys),
            suspicious_strings=dedupe_preserve_order(suspicious),
            external_resources=external_resources,
        )
        logger.info(
            "js.analyzed",
            fetch=len(analysis.fetch_calls),
            xhr=len(analysis.xhr_calls),
            axios=len(analysis.axios_calls),
            jquery=len(analysis.jquery_ajax_calls),
            tokens=len(analysis.exposed_tokens),
            keys=len(analysis.exposed_keys),
        )
        return analysis

    @staticmethod
    def _find_all(pattern: re.Pattern[str], blob: str) -> List[str]:
        """Return all capture-group-1 matches (or full matches) for a pattern."""

        results: List[str] = []
        for match in pattern.finditer(blob):
            # Prefer the first capturing group when present.
            results.append(match.group(1) if match.groups() else match.group(0))
        return results
