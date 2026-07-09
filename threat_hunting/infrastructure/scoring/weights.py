"""ScoringWeights.

Responsibility
--------------
Hold the configurable weights and multipliers the scoring engine applies. This
is pure data (loaded from ``config/scoring.yml``) so the scoring model is fully
tunable without touching code, satisfying "cada peso deverá ser configurável".
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScoringWeights(BaseModel):
    """Configurable weights for the scoring engine."""

    # Multiplier applied to each detection match type's own weight.
    rule_type_multipliers: dict[str, float] = Field(
        default_factory=lambda: {
            "regex": 1.0,
            "keyword": 1.0,
            "ioc": 1.0,
            "threat_actor": 1.2,
            "heuristic": 1.0,
            "yara": 1.3,
            "blacklist": 1.5,
        }
    )
    # Trust multiplier per source type (reputation/context).
    source_reputation: dict[str, float] = Field(
        default_factory=lambda: {
            "dark_web": 1.3,
            "paste_site": 1.2,
            "threat_feed": 1.25,
            "forum": 1.15,
            "marketplace": 1.2,
        }
    )
    # Bonus points when the finding carries many indicators (quantity of IOC).
    ioc_quantity_bonus: float = Field(default=2.0, description="Points per indicator (capped).")
    ioc_quantity_cap: float = Field(default=15.0)
    # Bonus for recurrence/history (findings seen before with same indicators).
    recurrence_bonus: float = Field(default=10.0)

    def multiplier_for_rule(self, rule_type: str) -> float:
        """Return the multiplier for a detection ``rule_type`` (default 1.0)."""
        return self.rule_type_multipliers.get(rule_type, 1.0)

    def reputation_for_source(self, source_type: str) -> float:
        """Return the reputation multiplier for a source type (default 1.0)."""
        return self.source_reputation.get(source_type, 1.0)
