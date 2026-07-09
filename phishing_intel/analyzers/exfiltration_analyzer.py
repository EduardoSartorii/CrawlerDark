"""Exfiltration analyzer for forms and JavaScript network destinations."""

from __future__ import annotations

from urllib.parse import urlparse

from phishing_intel.models.findings import DomFinding, ExfiltrationDestination, JavaScriptFinding


class ExfiltrationAnalyzer:
    """Detect and classify phishing data collection destinations."""

    def analyze(self, dom: DomFinding, javascript: JavaScriptFinding) -> list[ExfiltrationDestination]:
        """Return structured exfiltration destinations with confidence scores."""

        destinations: dict[str, ExfiltrationDestination] = {}
        for form in dom.forms:
            if form.action and form.method.lower() == "post":
                destinations[form.action] = ExfiltrationDestination(
                    destination=form.action,
                    destination_type=self._classify(form.action),
                    source="html_form_post",
                    confidence=85,
                )
        js_urls = (
            javascript.fetch_urls
            + javascript.xhr_urls
            + javascript.axios_urls
            + javascript.jquery_ajax_urls
            + javascript.hardcoded_urls
        )
        for url in js_urls:
            confidence = 90 if url in javascript.fetch_urls + javascript.axios_urls + javascript.jquery_ajax_urls else 65
            destinations.setdefault(
                url,
                ExfiltrationDestination(
                    destination=url,
                    destination_type=self._classify(url),
                    source="javascript_network_api",
                    confidence=confidence,
                ),
            )
        return sorted(destinations.values(), key=lambda item: (-item.confidence, item.destination))

    def _classify(self, destination: str) -> str:
        """Classify the destination transport or application channel."""

        value = destination.lower()
        if "telegram" in value or "discord" in value or "whatsapp" in value:
            return "messaging"
        if "mailto:" in value or "smtp" in value or "sendmail" in value:
            return "email"
        if "/api/" in value or "webhook" in value or value.endswith(".json"):
            return "api"
        parsed = urlparse(value)
        if parsed.scheme in {"http", "https"}:
            return "http"
        return "custom"
