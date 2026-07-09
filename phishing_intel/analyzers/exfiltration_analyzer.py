"""Exfiltration analyzer.

Component responsibility
------------------------
Fuse the DOM analysis (form POST targets) and the JavaScript analysis (network
calls, hardcoded URLs) into a single, classified list of exfiltration
destinations. Emits an
:class:`~phishing_intel.models.findings.ExfiltrationAnalysis`.

Channel classification
-----------------------
Each destination is labelled with an
:class:`~phishing_intel.models.findings.ExfiltrationChannel`:
* ``email``     - ``mailto:`` targets or e-mail send services.
* ``messaging`` - Telegram/Discord/Slack webhook endpoints.
* ``api``       - JSON/REST API-looking endpoints (``/api/``, ``fetch``...).
* ``http``      - plain HTTP(S) form POST endpoints.
* ``custom``    - anything else that still looks like a collection endpoint.
"""

from __future__ import annotations

import re
from typing import List, Optional

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import (
    DOMAnalysis,
    ExfiltrationAnalysis,
    ExfiltrationChannel,
    ExfiltrationDestination,
    JavaScriptAnalysis,
)

logger = get_logger(__name__)

# Messaging platforms frequently abused as free exfiltration back-ends.
_MESSAGING_RE = re.compile(
    r"(api\.telegram\.org|discord(?:app)?\.com/api/webhooks|hooks\.slack\.com)",
    re.I,
)
# Heuristic for API-style endpoints.
_API_RE = re.compile(r"(/api/|/v\d+/|\.json(\?|$)|/graphql|/rest/)", re.I)
# Common PHP/collector script names used by kits.
_COLLECTOR_RE = re.compile(
    r"(post\.php|send\.php|save\.php|next\.php|action\.php|process\.php|"
    r"gate\.php|panel\.php|result\.php|data\.php)",
    re.I,
)


class ExfiltrationAnalyzer:
    """Detect and classify exfiltration destinations."""

    def _classify_channel(self, destination: str) -> ExfiltrationChannel:
        """Map a destination string to an exfiltration channel.

        Business rule ordering matters: e-mail and messaging are the most
        specific signals and are checked first; API/HTTP are broader.
        """

        dest = destination.strip()
        lowered = dest.lower()
        if lowered.startswith("mailto:") or "sendmail" in lowered or "smtp" in lowered:
            return ExfiltrationChannel.EMAIL
        if _MESSAGING_RE.search(lowered):
            return ExfiltrationChannel.MESSAGING
        if _API_RE.search(lowered):
            return ExfiltrationChannel.API
        if lowered.startswith(("http://", "https://")):
            return ExfiltrationChannel.HTTP
        return ExfiltrationChannel.CUSTOM

    def _confidence_for(self, destination: str, channel: ExfiltrationChannel, source: str) -> int:
        """Assign a per-destination confidence score (0-100).

        Business rule: messaging/e-mail exfiltration is almost always malicious
        (high confidence); a form POST to a collector-named PHP script is a
        strong signal; a generic same-page action is weak.
        """

        base = {
            ExfiltrationChannel.EMAIL: 85,
            ExfiltrationChannel.MESSAGING: 95,
            ExfiltrationChannel.API: 70,
            ExfiltrationChannel.HTTP: 55,
            ExfiltrationChannel.CUSTOM: 40,
        }[channel]
        if _COLLECTOR_RE.search(destination):
            base = min(99, base + 20)
        # Findings coming from JavaScript network calls are slightly stronger
        # than a bare form action because they show active submission logic.
        if source.startswith("js."):
            base = min(99, base + 5)
        return base

    def analyze(
        self,
        dom: Optional[DOMAnalysis],
        js: Optional[JavaScriptAnalysis],
    ) -> ExfiltrationAnalysis:
        """Produce a structured, de-duplicated list of exfiltration targets.

        Parameters
        ----------
        dom:
            DOM analysis (for form ``action`` targets). May be ``None``.
        js:
            JavaScript analysis (for network calls / URLs). May be ``None``.

        Returns
        -------
        ExfiltrationAnalysis
        """

        destinations: List[ExfiltrationDestination] = []
        seen: set[str] = set()

        def add(destination: str, source: str) -> None:
            """Add a destination once, computing channel + confidence."""

            dest = (destination or "").strip()
            # Skip empties, pure fragments and JS void handlers.
            if not dest or dest in {"#", "javascript:void(0)", "javascript:;"}:
                return
            key = dest.lower()
            if key in seen:
                return
            seen.add(key)
            channel = self._classify_channel(dest)
            destinations.append(
                ExfiltrationDestination(
                    destination=dest,
                    channel=channel,
                    source=source,
                    confidence=self._confidence_for(dest, channel, source),
                )
            )

        # --- Form action targets -------------------------------------------
        if dom is not None:
            for form in dom.forms:
                if form.action:
                    add(form.action, "form.action")

        # --- JavaScript network calls --------------------------------------
        if js is not None:
            for call in js.fetch_calls:
                add(call, "js.fetch")
            for call in js.xhr_calls:
                add(call, "js.xhr")
            for call in js.axios_calls:
                add(call, "js.axios")
            for call in js.jquery_ajax_calls:
                add(call, "js.jquery")

        # Overall confidence is the strongest single destination signal.
        overall = max((d.confidence for d in destinations), default=0)
        analysis = ExfiltrationAnalysis(destinations=destinations, confidence=overall)
        logger.info(
            "exfil.analyzed",
            destinations=len(destinations),
            channels=sorted({d.channel.value for d in destinations}),
            confidence=overall,
        )
        return analysis
