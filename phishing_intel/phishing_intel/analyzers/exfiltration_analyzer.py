"""Exfiltration analyzer for destination classification and confidence."""

from __future__ import annotations

from urllib.parse import urlparse

from phishing_intel.models.findings import (
    DomAnalysisResult,
    ExfiltrationAnalysisResult,
    ExfiltrationDestination,
    ExfiltrationType,
    JavaScriptAnalysisResult,
)


class ExfiltrationAnalyzer:
    """Combines DOM and JavaScript indicators to detect data collection paths."""

    API_HINTS = ("api", "graphql", "v1/", "v2/", "collect", "submit")
    EMAIL_HINTS = ("mailto:", "@")
    MESSAGING_HINTS = ("telegram", "discord", "slack", "whatsapp")

    def analyze(self, dom: DomAnalysisResult, javascript: JavaScriptAnalysisResult) -> ExfiltrationAnalysisResult:
        """Return normalized exfiltration destinations with confidence score."""

        candidates = set()
        for form in dom.forms:
            if form.action:
                candidates.add(form.action)
        for group in (
            javascript.fetch_targets,
            javascript.xhr_targets,
            javascript.axios_targets,
            javascript.jquery_ajax_targets,
            javascript.hardcoded_urls,
        ):
            candidates.update(group)

        destinations = [self._classify_target(item) for item in sorted(candidates) if item]
        score = round(min(1.0, sum(dest.confidence for dest in destinations) / max(1, len(destinations))), 2)
        return ExfiltrationAnalysisResult(destinations=destinations, score=score)

    def _classify_target(self, target: str) -> ExfiltrationDestination:
        """Classify one destination target into exfiltration channel."""

        lowered = target.lower()
        if any(hint in lowered for hint in self.MESSAGING_HINTS):
            return ExfiltrationDestination(target=target, destination_type=ExfiltrationType.MESSAGING, confidence=0.85)
        if lowered.startswith(self.EMAIL_HINTS):
            return ExfiltrationDestination(target=target, destination_type=ExfiltrationType.EMAIL, confidence=0.8)

        parsed = urlparse(target)
        if parsed.scheme in {"http", "https"}:
            confidence = 0.9 if any(hint in lowered for hint in self.API_HINTS) else 0.7
            kind = ExfiltrationType.API if confidence > 0.8 else ExfiltrationType.HTTP
            return ExfiltrationDestination(target=target, destination_type=kind, confidence=confidence)

        return ExfiltrationDestination(target=target, destination_type=ExfiltrationType.CUSTOM, confidence=0.5)
