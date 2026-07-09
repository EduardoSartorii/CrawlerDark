"""
Severity Value Object
=====================

Represents the risk severity of a Finding.
Immutable, comparable, and derived from the numeric score.

Business Rule: severity is always derived from the scoring engine output.
The mapping thresholds are configurable via scoring.yaml.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Ordered severity levels — higher ordinal = more severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(
        cls,
        score: float,
        critical: float = 8.0,
        high: float = 6.0,
        medium: float = 4.0,
        low: float = 2.0,
    ) -> "Severity":
        """Derive severity from a numeric score using configurable thresholds.

        Args:
            score: Numeric risk score in the range [0, 10].
            critical: Minimum score for CRITICAL.
            high: Minimum score for HIGH.
            medium: Minimum score for MEDIUM.
            low: Minimum score for LOW.

        Returns:
            Corresponding Severity enum member.
        """
        if score >= critical:
            return cls.CRITICAL
        if score >= high:
            return cls.HIGH
        if score >= medium:
            return cls.MEDIUM
        if score >= low:
            return cls.LOW
        return cls.INFO

    @property
    def numeric(self) -> int:
        """Numeric ordinal for sorting/comparison (higher = more severe)."""
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __lt__(self, other: "Severity") -> bool:  # noqa: D105
        return self.numeric < other.numeric

    def __le__(self, other: "Severity") -> bool:  # noqa: D105
        return self.numeric <= other.numeric

    def __gt__(self, other: "Severity") -> bool:  # noqa: D105
        return self.numeric > other.numeric

    def __ge__(self, other: "Severity") -> bool:  # noqa: D105
        return self.numeric >= other.numeric
