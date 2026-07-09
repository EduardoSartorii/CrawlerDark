"""
Severity Value Object.

Represents the severity level of a threat finding.
In DDD, a Value Object is immutable and identified by its attributes, not by identity.
Severity encapsulates the business rules around threat criticality classification.

Business Rules:
    - Severity follows CVSS-inspired classification (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    - Numeric scores map to named levels for human readability
    - Comparison operators allow sorting and threshold checks
"""

from __future__ import annotations

from enum import IntEnum
from functools import total_ordering
from typing import ClassVar

from pydantic import field_validator
from pydantic.dataclasses import dataclass


@total_ordering
class SeverityLevel(IntEnum):
    """Ordered enumeration of threat severity levels."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_score(cls, score: float) -> "SeverityLevel":
        """
        Derive severity level from a numeric score in range [0.0, 10.0].

        Uses CVSS v3.1 thresholds as baseline, adapted for CTI context:
          0.0       → INFO
          0.1–3.9   → LOW
          4.0–6.9   → MEDIUM
          7.0–8.9   → HIGH
          9.0–10.0  → CRITICAL
        """
        if score < 0.1:
            return cls.INFO
        if score < 4.0:
            return cls.LOW
        if score < 7.0:
            return cls.MEDIUM
        if score < 9.0:
            return cls.HIGH
        return cls.CRITICAL

    @property
    def label(self) -> str:
        """Human-readable label."""
        return self.name.capitalize()

    @property
    def color(self) -> str:
        """Terminal/UI color code for the severity level."""
        _colors: dict[str, str] = {
            "INFO": "blue",
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange",
            "CRITICAL": "red",
        }
        return _colors[self.name]


@dataclass(frozen=True)
class Severity:
    """
    Immutable value object encapsulating a severity level with its numeric representation.

    Architectural note: frozen dataclass ensures immutability — a core DDD VO constraint.
    """

    level: SeverityLevel

    SCORE_MAP: ClassVar[dict[SeverityLevel, tuple[float, float]]] = {
        SeverityLevel.INFO: (0.0, 0.0),
        SeverityLevel.LOW: (0.1, 3.9),
        SeverityLevel.MEDIUM: (4.0, 6.9),
        SeverityLevel.HIGH: (7.0, 8.9),
        SeverityLevel.CRITICAL: (9.0, 10.0),
    }

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        """Factory method: construct Severity from numeric score."""
        return cls(level=SeverityLevel.from_score(score))

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Factory method: construct Severity from string label."""
        try:
            level = SeverityLevel[value.upper()]
        except KeyError as exc:
            valid = [l.name for l in SeverityLevel]
            raise ValueError(f"Invalid severity '{value}'. Valid: {valid}") from exc
        return cls(level=level)

    @classmethod
    def critical(cls) -> "Severity":
        return cls(level=SeverityLevel.CRITICAL)

    @classmethod
    def high(cls) -> "Severity":
        return cls(level=SeverityLevel.HIGH)

    @classmethod
    def medium(cls) -> "Severity":
        return cls(level=SeverityLevel.MEDIUM)

    @classmethod
    def low(cls) -> "Severity":
        return cls(level=SeverityLevel.LOW)

    @classmethod
    def info(cls) -> "Severity":
        return cls(level=SeverityLevel.INFO)

    def __lt__(self, other: "Severity") -> bool:
        return self.level < other.level

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.level == other.level

    def __hash__(self) -> int:
        return hash(self.level)

    def __str__(self) -> str:
        return self.level.label

    def __repr__(self) -> str:
        return f"Severity(level={self.level.name})"

    @property
    def value(self) -> int:
        """Numeric integer value (0-4)."""
        return self.level.value

    @property
    def score_range(self) -> tuple[float, float]:
        """Score range (min, max) for this severity level."""
        return self.SCORE_MAP[self.level]

    def is_at_least(self, threshold: "Severity") -> bool:
        """Check if this severity meets or exceeds a threshold."""
        return self.level >= threshold.level
