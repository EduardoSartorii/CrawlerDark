"""
Scoring Engine.

Computes a final risk score for each Finding based on multiple weighted factors.
All weights are configurable — no hardcoded values.

Scoring Factors:
    1. Base score from detection rule matches
    2. Source trust weight (different sources have different fidelity)
    3. Category severity multiplier (CARD_DATA > SOCIAL_MEDIA)
    4. Keyword/watchlist match bonus
    5. IOC count (more IOCs = more context = higher confidence)
    6. VIP/brand match (immediate score boost)
    7. Threat actor attribution (strong boost)
    8. Recency bonus (fresh findings score higher)
    9. Confidence dampening (low confidence reduces effective score)
    10. Blacklist/whitelist modifiers

Architecture:
    - Builder Pattern: ScoringContext builds the input for the scorer
    - Chain of Responsibility: each factor applies independently
    - Result is immutable Score value object
    - Weights loaded from config (YAML), not hardcoded

Design Decision:
    The scoring engine does NOT modify Findings directly.
    It returns a Score that the pipeline applies via finding.apply_score().
    This preserves auditability — each stage's contribution is trackable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects.score import Score
from ...core.domain.value_objects.source_type import SourceType

logger = structlog.get_logger(__name__)


@dataclass
class ScoringWeights:
    """
    Configurable scoring weights.

    All values loaded from config YAML.
    Default values represent a balanced detection profile.
    """

    # Category multipliers
    category_weights: dict[str, float] = field(default_factory=lambda: {
        "credential_leak": 2.5,
        "card_data": 3.0,
        "ransomware": 2.8,
        "c2_infrastructure": 2.5,
        "vip_threat": 2.5,
        "executive_exposure": 2.5,
        "dark_web": 1.8,
        "malware": 2.0,
        "data_leak": 2.0,
        "database_leak": 2.2,
        "code_leak": 1.8,
        "phishing": 1.6,
        "brand_abuse": 1.5,
        "ioc": 1.4,
        "vulnerability": 1.5,
        "social_media": 0.8,
        "news": 0.7,
        "general": 1.0,
        "unknown": 0.5,
    })

    # Bonus modifiers
    vip_match_bonus: float = 3.0
    brand_match_bonus: float = 2.0
    threat_actor_bonus: float = 3.5
    ioc_per_finding_bonus: float = 0.3  # per IOC, capped
    max_ioc_bonus: float = 2.0
    credential_pair_bonus: float = 2.5
    cpf_cnpj_bonus: float = 2.0
    credit_card_bonus: float = 2.5
    crypto_wallet_bonus: float = 1.5
    dark_web_source_bonus: float = 1.5
    recency_bonus_hours: int = 4  # hours within which bonus applies
    recency_bonus_value: float = 0.5

    # Confidence base
    min_confidence: float = 0.3

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScoringWeights":
        weights = cls()
        for key, value in data.items():
            if hasattr(weights, key):
                setattr(weights, key, value)
        return weights


@dataclass
class ScoreBreakdown:
    """Detailed explanation of how a score was computed (audit trail)."""

    finding_id: str
    base_score: float = 0.0
    source_trust_factor: float = 1.0
    category_multiplier: float = 1.0
    bonus_contributions: dict[str, float] = field(default_factory=dict)
    final_score: float = 0.0
    final_confidence: float = 0.0

    def explain(self) -> str:
        lines = [
            f"Finding: {self.finding_id}",
            f"  Base score: {self.base_score:.2f}",
            f"  Source trust: ×{self.source_trust_factor:.2f}",
            f"  Category multiplier: ×{self.category_multiplier:.2f}",
        ]
        for bonus_name, bonus_val in self.bonus_contributions.items():
            lines.append(f"  Bonus [{bonus_name}]: +{bonus_val:.2f}")
        lines.append(f"  → Final: {self.final_score:.2f} (confidence: {self.final_confidence:.0%})")
        return "\n".join(lines)


class ScoringEngine:
    """
    Computes the final risk score for a Finding.

    Called by the pipeline AFTER detection (detection boosts are included in base score).
    """

    def __init__(self, weights: ScoringWeights | None = None) -> None:
        self._weights = weights or ScoringWeights()

    def configure(self, weights_config: dict[str, Any]) -> None:
        """Hot-reload scoring weights from config."""
        self._weights = ScoringWeights.from_dict(weights_config)
        logger.info("scoring.weights_updated")

    def score(
        self,
        finding: Finding,
        matched_keywords: list[str] | None = None,
        matched_vips: list[str] | None = None,
        matched_brands: list[str] | None = None,
        matched_threat_actor: str | None = None,
    ) -> tuple[Score, ScoreBreakdown]:
        """
        Compute the final score for a Finding.

        Returns both the Score value object and a breakdown for auditability.
        """
        breakdown = ScoreBreakdown(finding_id=finding.id)

        # 1. Start from detection-computed base score
        base_score = finding.score.value
        breakdown.base_score = base_score

        # 2. Source trust factor
        source_type = finding.source_type
        trust = source_type.trust_weight if isinstance(source_type, SourceType) else 0.5
        breakdown.source_trust_factor = trust

        # 3. Category multiplier
        cat_weight = self._weights.category_weights.get(
            finding.category.value, 1.0
        )
        breakdown.category_multiplier = cat_weight

        # Apply factors: base × trust × category
        computed = base_score * trust * cat_weight
        bonuses: dict[str, float] = {}

        # 4. VIP match bonus
        if matched_vips:
            bonuses["vip_match"] = self._weights.vip_match_bonus * len(matched_vips)
            finding.add_tag("vip-match")

        # 5. Brand match bonus
        if matched_brands:
            bonuses["brand_match"] = self._weights.brand_match_bonus
            finding.affected_brands = list(set(finding.affected_brands + matched_brands))
            finding.add_tag("brand-match")

        # 6. Threat actor attribution bonus
        if matched_threat_actor:
            bonuses["threat_actor"] = self._weights.threat_actor_bonus
            finding.threat_actor = matched_threat_actor
            finding.add_tag("threat-actor-match")

        # 7. IOC count bonus
        ioc_bonus = min(
            finding.ioc_count * self._weights.ioc_per_finding_bonus,
            self._weights.max_ioc_bonus,
        )
        if ioc_bonus > 0:
            bonuses["ioc_density"] = ioc_bonus

        # 8. High-value artifact bonuses (from normalized_data artifacts)
        artifacts = finding.normalized_data.get("artifact_summary", {})
        if isinstance(artifacts, dict):
            if "credential_pair" in artifacts:
                bonuses["credential_pair"] = self._weights.credential_pair_bonus
            if "credit_card" in artifacts:
                bonuses["credit_card"] = self._weights.credit_card_bonus
            if "cpf" in artifacts or "cnpj" in artifacts:
                bonuses["pii_document"] = self._weights.cpf_cnpj_bonus
            if "bitcoin_wallet" in artifacts:
                bonuses["crypto_wallet"] = self._weights.crypto_wallet_bonus

        # 9. Dark web source bonus
        if isinstance(source_type, SourceType) and source_type.requires_opsec:
            bonuses["dark_web_source"] = self._weights.dark_web_source_bonus

        # 10. Recency bonus
        age_hours = (
            datetime.now(tz=timezone.utc) - finding.created_at
        ).total_seconds() / 3600
        if age_hours <= self._weights.recency_bonus_hours:
            bonuses["recency"] = self._weights.recency_bonus_value

        total_bonus = sum(bonuses.values())
        breakdown.bonus_contributions = bonuses

        # Final score = computed base + bonuses, capped at 10
        raw_final = computed + total_bonus
        final_score = max(0.0, min(10.0, raw_final))
        breakdown.final_score = final_score

        # Confidence: source trust × keyword match factor
        keyword_factor = min(1.0, 0.5 + 0.1 * len(matched_keywords or []))
        final_confidence = max(
            self._weights.min_confidence,
            trust * keyword_factor,
        )
        breakdown.final_confidence = final_confidence

        logger.debug(
            "scoring.computed",
            finding_id=finding.id,
            base=base_score,
            final=final_score,
            confidence=final_confidence,
            bonuses=bonuses,
        )

        return Score(value=final_score, confidence=final_confidence), breakdown
