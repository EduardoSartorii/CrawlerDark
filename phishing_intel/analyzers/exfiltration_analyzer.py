"""
Exfiltration endpoint analyzer.

Detects and classifies data exfiltration destinations from forms,
JavaScript network calls, and embedded endpoints.

Architectural Responsibility:
    Identifies where stolen credentials/data are sent,
    critical for infrastructure takedown and operator attribution.

Exfiltration Types:
    - HTTP (form POST)
    - API (REST endpoints)
    - Email (mailto, form email)
    - Messaging (Telegram, Discord webhooks)
    - Custom (obfuscated or non-standard)
"""

from __future__ import annotations

import re

import structlog

from phishing_intel.models.findings import (
    DOMFinding,
    ExfiltrationDestination,
    ExfiltrationFinding,
    ExfiltrationType,
    JavaScriptFinding,
)

logger = structlog.get_logger(__name__)


class ExfiltrationAnalyzer:
    """
    Data exfiltration detection and classification engine.

    Correlates form actions and JavaScript network calls to
    identify credential/data collection endpoints.
    """

    # Messaging platform patterns
    MESSAGING_PATTERNS = [
        (re.compile(r"api\.telegram\.org", re.I), "telegram"),
        (re.compile(r"discord\.com/api/webhooks", re.I), "discord"),
        (re.compile(r"hooks\.slack\.com", re.I), "slack"),
    ]

    EMAIL_PATTERN = re.compile(r"mailto:|@.*\.(com|org|net|br)", re.I)
    API_PATTERN = re.compile(r"/api/|/v\d+/|graphql|rest", re.I)

    def analyze(
        self,
        dom: DOMFinding,
        javascript: JavaScriptFinding,
    ) -> ExfiltrationFinding:
        """
        Analyze exfiltration destinations from DOM and JavaScript.

        Args:
            dom: DOM analysis with forms.
            javascript: JavaScript analysis with network calls.

        Returns:
            ExfiltrationFinding with classified destinations.
        """
        logger.info("exfiltration_analysis_start")

        destinations: list[ExfiltrationDestination] = []

        # Form POST destinations (primary exfiltration vector)
        for form in dom.forms:
            if form.action:
                dest = self._classify_destination(
                    form.action,
                    method=form.method,
                    source="form",
                )
                # Form POST destinations get higher confidence
                dest.confidence = min(dest.confidence + 20, 100.0)
                destinations.append(dest)

        # JavaScript network destinations
        js_urls = (
            javascript.fetch_calls
            + javascript.xhr_urls
            + javascript.ajax_urls
            + javascript.axios_urls
        )
        for url in js_urls:
            destinations.append(
                self._classify_destination(url, method="POST", source="javascript")
            )

        # Deduplicate by URL
        seen: set[str] = set()
        unique: list[ExfiltrationDestination] = []
        for dest in destinations:
            if dest.url not in seen:
                seen.add(dest.url)
                unique.append(dest)

        # Determine primary method and overall confidence
        primary = self._determine_primary(unique)
        overall = max((d.confidence for d in unique), default=0.0)

        finding = ExfiltrationFinding(
            destinations=unique,
            primary_method=primary,
            overall_confidence=overall,
        )

        logger.info(
            "exfiltration_analysis_complete",
            destination_count=len(unique),
            primary_method=primary.value if primary else None,
        )
        return finding

    def _classify_destination(
        self,
        url: str,
        method: str = "POST",
        source: str = "",
    ) -> ExfiltrationDestination:
        """
        Classify a single exfiltration destination.

        Business rules:
            - Telegram/Discord webhooks -> Messaging (high confidence)
            - mailto: links -> Email
            - /api/ paths -> API
            - Form POST -> HTTP (high confidence)
        """
        exfil_type = ExfiltrationType.HTTP
        confidence = 50.0

        for pattern, platform in self.MESSAGING_PATTERNS:
            if pattern.search(url):
                exfil_type = ExfiltrationType.MESSAGING
                confidence = 90.0
                break

        if exfil_type == ExfiltrationType.HTTP:
            if self.EMAIL_PATTERN.search(url):
                exfil_type = ExfiltrationType.EMAIL
                confidence = 75.0
            elif self.API_PATTERN.search(url):
                exfil_type = ExfiltrationType.API
                confidence = 80.0
            elif method.upper() == "POST":
                confidence = 70.0

        if not url.startswith("http") and not url.startswith("mailto"):
            exfil_type = ExfiltrationType.CUSTOM
            confidence = 40.0

        return ExfiltrationDestination(
            url=url,
            method=method,
            exfiltration_type=exfil_type,
            confidence=confidence,
            source=source,
        )

    def _determine_primary(
        self, destinations: list[ExfiltrationDestination]
    ) -> ExfiltrationType | None:
        """Determine primary exfiltration method by highest confidence."""
        if not destinations:
            return None
        return max(destinations, key=lambda d: d.confidence).exfiltration_type
