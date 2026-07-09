"""
Score Value Object
==================

Encapsulates the numeric risk score of a Finding together with a
confidence level. The score is produced by the ScoringEngine and is
immutable once assigned.

Business rules:
- Score range: [0.0, 10.0]
- Confidence range: [0.0, 1.0]
- A score of 0 with confidence 0 indicates "not yet scored".
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, order=True)
class Score:
    """Immutable numeric risk score with confidence."""

    value: float = field(default=0.0)
    confidence: float = field(default=0.0)

    def __post_init__(self) -> None:
        if not (0.0 <= self.value <= 10.0):
            raise ValueError(f"Score.value must be in [0, 10], got {self.value}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Score.confidence must be in [0, 1], got {self.confidence}")

    @classmethod
    def zero(cls) -> "Score":
        """Unscored sentinel value."""
        return cls(value=0.0, confidence=0.0)

    @classmethod
    def from_raw(cls, value: float, confidence: float = 1.0) -> "Score":
        """Clamp raw values into valid ranges and return a Score."""
        return cls(
            value=max(0.0, min(10.0, value)),
            confidence=max(0.0, min(1.0, confidence)),
        )

    def __add__(self, other: "Score") -> "Score":
        """Combine two scores by summing values and averaging confidence."""
        combined_value = min(10.0, self.value + other.value)
        avg_confidence = (self.confidence + other.confidence) / 2
        return Score(value=combined_value, confidence=avg_confidence)

    def weighted(self, weight: float) -> "Score":
        """Apply a multiplier weight to the score value."""
        return Score.from_raw(self.value * weight, self.confidence)

    @property
    def is_scored(self) -> bool:
        """True when the score has been computed."""
        return self.value > 0.0 or self.confidence > 0.0

    def __repr__(self) -> str:
        return f"Score(value={self.value:.2f}, confidence={self.confidence:.2f})"
