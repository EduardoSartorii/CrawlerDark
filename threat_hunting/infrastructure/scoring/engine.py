"""Weighted, explainable scoring engine.

Responsibility
--------------
Implement :class:`ScoringEnginePort`. It converts detection results and extracted
indicators into a 0-100 :class:`Score` using **fully configurable weights**
(:class:`ScoringWeights`). Every point is attributed to a named contributor and
stored in ``finding.metadata['scoring']`` so scores are transparent and tunable
without code changes.

Business rules
--------------
* Each contributor has its own weight; per-indicator contribution is capped so a
  single noisy dump cannot dominate the score.
* Severity is derived from the final score by the domain (``Severity.from_score``).
* Confidence is nudged up when high-signal artefacts (credentials, cards,
  documents, actor mentions) are present.
"""

from __future__ import annotations

from collections import Counter

from threat_hunting.core.application.ports.pipeline_stages import ScoringEnginePort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import ConfidenceLevel, IndicatorType
from threat_hunting.core.domain.value_objects import Score
from threat_hunting.infrastructure.config.settings import ScoringWeights

_IOC_LIKE = {
    IndicatorType.IPV4,
    IndicatorType.IPV6,
    IndicatorType.URL,
    IndicatorType.DOMAIN,
    IndicatorType.MD5,
    IndicatorType.SHA1,
    IndicatorType.SHA256,
    IndicatorType.CVE,
}
_HIGH_SIGNAL = {
    IndicatorType.CREDENTIAL,
    IndicatorType.CREDIT_CARD,
    IndicatorType.CPF,
    IndicatorType.CNPJ,
}


class WeightedScoringEngine(ScoringEnginePort):
    """Computes an explainable, configurable score for a finding."""

    def __init__(self, weights: ScoringWeights) -> None:
        self._w = weights

    def score(self, finding: Finding) -> Finding:
        """Compute, attribute and set the finding's score and severity."""
        contributions: dict[str, float] = {}
        detection = finding.metadata.get("detection", {})

        self._score_detection(detection, contributions)
        self._score_indicators(finding, contributions)
        self._score_context(finding, detection, contributions)

        total = Score.from_contributions(contributions)
        finding.metadata["scoring"] = {
            "contributions": {k: round(v, 2) for k, v in contributions.items()},
            "total": total.value,
        }
        finding.set_score(total.value)
        finding.confidence = self._confidence(finding, total)
        return finding

    # -- contributors ------------------------------------------------------

    def _score_detection(self, detection: dict, contributions: dict[str, float]) -> None:
        """Score detection matches (rules, keywords, VIPs, actors, ...)."""
        if detection.get("blacklisted"):
            contributions["blacklist"] = 50.0
        if detection.get("rules"):
            contributions["regex_match"] = self._w.regex_match * len(detection["rules"])
        if detection.get("keywords"):
            contributions["keyword_match"] = self._w.keyword_match * len(
                detection["keywords"]
            )
        if detection.get("vips"):
            contributions["vip_match"] = self._w.vip_match * len(detection["vips"])
        if detection.get("actors"):
            contributions["threat_actor"] = self._w.threat_actor * len(
                detection["actors"]
            )
        if detection.get("brands"):
            contributions["brand"] = self._w.context * len(detection["brands"])

    def _score_indicators(self, finding: Finding, contributions: dict[str, float]) -> None:
        """Score by indicator type, capping per-type contribution."""
        counts = Counter(i.type for i in finding.indicators)
        type_weight = {
            IndicatorType.CREDENTIAL: ("credential", self._w.credential),
            IndicatorType.CREDIT_CARD: ("credit_card", self._w.credit_card),
            IndicatorType.EMAIL: ("email", self._w.email),
            IndicatorType.CPF: ("cpf", self._w.cpf),
            IndicatorType.CNPJ: ("cnpj", self._w.cnpj),
            IndicatorType.DOMAIN: ("domain", self._w.domain),
        }
        for ioc_type, count in counts.items():
            if ioc_type in type_weight:
                name, weight = type_weight[ioc_type]
                contributions[name] = min(weight * count, self._w.per_indicator_cap)
            elif ioc_type in _IOC_LIKE:
                contributions["ioc_match"] = (
                    contributions.get("ioc_match", 0.0)
                    + min(self._w.ioc_match * count, self._w.per_indicator_cap)
                )

        total_iocs = sum(counts.values())
        if total_iocs:
            contributions["ioc_volume"] = min(
                self._w.ioc_volume * total_iocs, self._w.per_indicator_cap
            )

    def _score_context(
        self, finding: Finding, detection: dict, contributions: dict[str, float]
    ) -> None:
        """Score source reputation and recurrence/history signals."""
        reputation = float(finding.metadata.get("source_reputation", 0.0))
        if reputation:
            contributions["source_reputation"] = self._w.source_reputation * reputation
        if finding.metadata.get("recurrence"):
            contributions["recurrence"] = self._w.recurrence
        if finding.metadata.get("seen_before"):
            contributions["history"] = self._w.history

    @staticmethod
    def _confidence(finding: Finding, total: Score) -> ConfidenceLevel:
        """Derive confidence from score band and presence of high-signal IOCs."""
        has_high_signal = any(i.type in _HIGH_SIGNAL for i in finding.indicators)
        if total.value >= 85 and has_high_signal:
            return ConfidenceLevel.CONFIRMED
        if total.value >= 60:
            return ConfidenceLevel.HIGH
        if total.value >= 30:
            return ConfidenceLevel.MEDIUM
        if total.value > 0:
            return ConfidenceLevel.LOW
        return finding.confidence
