"""
Score Value Object.

Represents the intelligence confidence/risk score assigned to a Finding.
Encapsulates scoring business rules: normalization, combining, thresholds.

Design Notes:
    - Immutable (frozen dataclass)
    - Range: 0.0 (no threat) to 10.0 (confirmed critical threat)
    - Confidence: 0.0 to 1.0 (certainty of the finding)
    - Combined risk = score * confidence (adjusted risk)
"""

from __future__ import annotations

from pydantic.dataclasses import dataclass


@dataclass(frozen=True)
class Score:
    """
    Immutable score value object.

    Attributes:
        value: Raw threat score in range [0.0, 10.0].
        confidence: Confidence level in range [0.0, 1.0].
    """

    value: float
    confidence: float = 1.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", max(0.0, min(10.0, self.value)))
        object.__setattr__(self, "confidence", max(0.0, min(1.0, self.confidence)))

    @classmethod
    def zero(cls) -> "Score":
        return cls(value=0.0, confidence=0.0)

    @classmethod
    def maximum(cls) -> "Score":
        return cls(value=10.0, confidence=1.0)

    @property
    def adjusted(self) -> float:
        """Risk-adjusted score: value × confidence, normalized to [0, 10]."""
        return round(self.value * self.confidence, 2)

    @property
    def is_above_threshold(self) -> bool:
        """Default alerting threshold: adjusted score ≥ 5.0."""
        return self.adjusted >= 5.0

    def boost(self, amount: float) -> "Score":
        """Return a new Score with value boosted by amount (capped at 10)."""
        return Score(value=self.value + amount, confidence=self.confidence)

    def penalize(self, amount: float) -> "Score":
        """Return a new Score with value reduced by amount (floor 0)."""
        return Score(value=self.value - amount, confidence=self.confidence)

    def with_confidence(self, confidence: float) -> "Score":
        """Return a new Score with updated confidence."""
        return Score(value=self.value, confidence=confidence)

    @classmethod
    def combine(cls, scores: list["Score"], strategy: str = "weighted_avg") -> "Score":
        """
        Combine multiple scores into a single representative score.

        Strategies:
            - weighted_avg: confidence-weighted average
            - max: highest adjusted score
            - sum_capped: sum capped at 10
        """
        if not scores:
            return cls.zero()

        if strategy == "max":
            best = max(scores, key=lambda s: s.adjusted)
            return cls(value=best.value, confidence=best.confidence)

        if strategy == "sum_capped":
            total = sum(s.value for s in scores)
            avg_conf = sum(s.confidence for s in scores) / len(scores)
            return cls(value=total, confidence=avg_conf)

        # Default: weighted average
        total_weight = sum(s.confidence for s in scores) or 1.0
        weighted_value = sum(s.value * s.confidence for s in scores) / total_weight
        avg_confidence = sum(s.confidence for s in scores) / len(scores)
        return cls(value=weighted_value, confidence=avg_confidence)

    def __str__(self) -> str:
        return f"{self.value:.1f} (conf: {self.confidence:.0%})"

    def __repr__(self) -> str:
        return f"Score(value={self.value}, confidence={self.confidence})"

    def __lt__(self, other: "Score") -> bool:
        return self.adjusted < other.adjusted

    def __le__(self, other: "Score") -> bool:
        return self.adjusted <= other.adjusted

    def __gt__(self, other: "Score") -> bool:
        return self.adjusted > other.adjusted

    def __ge__(self, other: "Score") -> bool:
        return self.adjusted >= other.adjusted
