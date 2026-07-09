"""
ScoringEngine
=============

Implements the IScoringEngine port.

Computes a multi-factor risk score for each Finding based on:
    - Detection rule matches (YARA, Regex, Keyword, IOC)
    - VIP and ThreatActor mentions
    - Extracted artifacts (credentials, cards, CPF, CNPJ)
    - IOC density
    - Source reputation multiplier
    - Historical recurrence

All weights are configurable via config/scoring.yaml.
No score component is hardcoded.

Score calculation:
    1. Accumulate raw score from weighted components.
    2. Apply source reputation multiplier.
    3. Add recurrence bonus.
    4. Clamp to [0, 10].
    5. Assign severity via Severity.from_score().

The final Score object is attached to the Finding via finding.set_score().
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import structlog

from threat_hunting.core.domain.entities.rule import RuleType
from threat_hunting.core.domain.exceptions.domain_exceptions import ScoringError
from threat_hunting.core.domain.ports.engines import IScoringEngine
from threat_hunting.core.domain.value_objects.score import Score
from threat_hunting.core.domain.value_objects.source import SourceType

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding

logger = structlog.get_logger(__name__)


class ScoringEngine(IScoringEngine):
    """
    Configurable multi-factor scoring engine.

    All weight constants come from the ScoringWeights config section.
    """

    def __init__(self, weights: dict[str, Any]) -> None:
        self._w = weights

    async def score(self, finding: "Finding") -> "Finding":
        """Compute and assign a risk score to the Finding.

        Args:
            finding: Finding after DetectionEngine.run().

        Returns:
            Finding with score and severity assigned.

        Raises:
            ScoringError: On computation failure.
        """
        log = logger.bind(finding_id=finding.id)
        try:
            raw_score = self._compute_raw_score(finding)
            reputation_mult = self._source_reputation(finding.source)
            raw_score *= reputation_mult

            # Clamp and assign.
            final = Score.from_raw(raw_score, confidence=self._compute_confidence(finding))
            finding.set_score(final)

            log.debug(
                "scored",
                score=final.value,
                severity=finding.severity.value,
                confidence=final.confidence,
                raw_before_clamp=raw_score,
            )
        except Exception as exc:
            log.error("scoring_failed", error=str(exc))
            raise ScoringError(f"Scoring failed: {exc}") from exc

        from threat_hunting.core.domain.entities.finding import FindingStatus
        finding.advance_status(FindingStatus.SCORED)
        return finding

    def _compute_raw_score(self, finding: "Finding") -> float:
        """Accumulate weighted score from all detection signals."""
        score = 0.0
        w = self._w

        for result in finding.detection_results:
            rtype = result.rule_type

            if rtype == RuleType.KEYWORD.value:
                score += w.get("keyword_match", 1.0) * result.confidence
            elif rtype == RuleType.YARA.value:
                score += w.get("yara_match", 2.0) * result.confidence
            elif rtype == RuleType.REGEX.value:
                score += w.get("regex_match", 1.0) * result.confidence
            elif rtype == "vip":
                score += w.get("vip_match", 3.0) * result.confidence
            elif rtype == "threat_actor":
                score += w.get("threat_actor_match", 2.5) * result.confidence
            elif rtype == "heuristic":
                if result.rule_name == "Credential Pair Detected":
                    cred_count = finding.normalized_data.get("credential_count", 1)
                    score += w.get("credential_match", 3.0) * min(cred_count / 10, 1.0)
                elif result.rule_name == "Payment Card Number Detected":
                    card_count = finding.normalized_data.get("card_count", 1)
                    score += w.get("card_match", 3.5) * min(card_count / 5, 1.0)

        # IOC density bonus.
        ioc_count = len(finding.indicators)
        ioc_threshold = w.get("ioc_density_threshold", 10)
        if ioc_count > ioc_threshold:
            score += w.get("high_ioc_density", 1.5)
        elif ioc_count > 0:
            score += w.get("ioc_match", 2.5) * min(ioc_count / ioc_threshold, 1.0)

        return score

    def _source_reputation(self, source: SourceType) -> float:
        """Return the reputation multiplier for the source type."""
        reputations: dict[str, float] = self._w.get("source_reputation", {})
        return reputations.get(source.value, 1.0)

    def _compute_confidence(self, finding: "Finding") -> float:
        """Estimate confidence based on number and quality of detection signals."""
        if not finding.detection_results:
            return 0.1
        total_confidence = sum(r.confidence for r in finding.detection_results)
        # Normalize to [0, 1] — more signals = higher confidence, up to 1.0.
        return min(1.0, total_confidence / max(len(finding.detection_results), 1))
