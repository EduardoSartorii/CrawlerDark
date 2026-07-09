"""Scoring engine — configurable risk scoring."""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from threat_hunting.core.contracts.services import IScoringEngine
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import IndicatorType, Severity, SourceType

if TYPE_CHECKING:
    from threat_hunting.core.contracts.repositories import IScoreProfileRepository

logger = structlog.get_logger(__name__)

DEFAULT_WEIGHTS: dict[str, float] = {
    "regex_match": 10.0,
    "yara_match": 15.0,
    "vip_match": 25.0,
    "ioc_match": 12.0,
    "credential": 20.0,
    "card": 25.0,
    "email": 8.0,
    "document": 10.0,
    "cpf": 15.0,
    "cnpj": 15.0,
    "domain": 5.0,
    "threat_actor": 20.0,
    "source_reputation": 10.0,
    "context": 5.0,
    "ioc_quantity": 3.0,
    "recurrence": 8.0,
    "history": 5.0,
}

SOURCE_REPUTATION: dict[str, float] = {
    SourceType.DARKWEB.value: 1.5,
    SourceType.DEEPWEB.value: 1.3,
    SourceType.MARKETPLACE.value: 1.4,
    SourceType.PASTE.value: 1.2,
    SourceType.FORUM.value: 1.1,
    SourceType.SOCIAL.value: 0.8,
    SourceType.API.value: 1.0,
}


class ScoringEngine(IScoringEngine):
    """Calculates configurable risk scores for findings."""

    def __init__(self, profile_repo: IScoreProfileRepository) -> None:
        self._profile_repo = profile_repo

    async def score(self, finding: Finding) -> Finding:
        profile = await self._profile_repo.get_default()
        weights = {w.dimension: w.weight for w in profile.weights if w.enabled}
        if not weights:
            weights = DEFAULT_WEIGHTS

        score = 0.0
        content = f"{finding.title} {finding.description}"

        # IOC-based scoring
        for indicator in finding.indicators:
            dim_map = {
                IndicatorType.EMAIL: "email",
                IndicatorType.CARD: "card",
                IndicatorType.CPF: "cpf",
                IndicatorType.CNPJ: "cnpj",
                IndicatorType.DOMAIN: "domain",
            }
            dim = dim_map.get(indicator.type, "ioc_match")
            score += weights.get(dim, weights.get("ioc_match", 10.0))

        score += len(finding.indicators) * weights.get("ioc_quantity", 3.0)

        # Rule match scoring
        matched_rules = finding.metadata.get("matched_rules", [])
        score += len(matched_rules) * weights.get("regex_match", 10.0)

        # Watchlist/VIP scoring
        vip_tags = [t for t in finding.tags if t.startswith("watchlist:vip")]
        score += len(vip_tags) * weights.get("vip_match", 25.0)

        # Source reputation
        rep = SOURCE_REPUTATION.get(finding.source.value, 1.0)
        score += weights.get("source_reputation", 10.0) * rep

        # Threat actor tags
        if any("threat_actor" in t for t in finding.tags):
            score += weights.get("threat_actor", 20.0)

        # Credential/card keywords
        if any(kw in content.lower() for kw in ("password", "credential", "leak")):
            score += weights.get("credential", 20.0)
        if any(kw in content.lower() for kw in ("card", "cvv", "credit")):
            score += weights.get("card", 25.0)

        finding.score = min(100.0, score)
        finding.confidence = min(1.0, finding.score / 100.0)

        if finding.score >= 80:
            finding.severity = Severity.CRITICAL
        elif finding.score >= 60:
            finding.severity = Severity.HIGH
        elif finding.score >= 40:
            finding.severity = Severity.MEDIUM
        elif finding.score >= 20:
            finding.severity = Severity.LOW

        finding.add_timeline_event("scoring", f"Score: {finding.score:.1f}")
        logger.info("scoring.completed", finding_id=str(finding.id), score=finding.score)
        return finding
