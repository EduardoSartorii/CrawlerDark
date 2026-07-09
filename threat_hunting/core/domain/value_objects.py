"""Domain value objects.

Responsibility
--------------
Model immutable, self-validating quantities that carry business meaning. Value
objects have no identity: two ``Score`` instances with the same value are equal.

Business rules
--------------
* A ``Score`` is always clamped to the inclusive range ``[0, 100]``.
* Scores compose additively but never exceed the range (fraud-scoring engines
  must not overflow when many contributors fire at once).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Mapping


@dataclass(frozen=True, slots=True, order=True)
class Score:
    """A normalised 0-100 risk score.

    The value is validated and clamped on construction, guaranteeing that no
    downstream consumer ever has to defend against out-of-range scores.
    """

    value: float

    MIN: ClassVar[float] = 0.0
    MAX: ClassVar[float] = 100.0

    def __post_init__(self) -> None:
        clamped = max(self.MIN, min(self.MAX, float(self.value)))
        # ``frozen`` dataclasses forbid normal attribute assignment.
        object.__setattr__(self, "value", round(clamped, 2))

    def __add__(self, other: "Score | float | int") -> "Score":
        other_value = other.value if isinstance(other, Score) else float(other)
        return Score(self.value + other_value)

    def __float__(self) -> float:
        return self.value

    @classmethod
    def zero(cls) -> "Score":
        """Return the neutral score (0)."""
        return cls(0.0)

    @classmethod
    def from_contributions(cls, contributions: Mapping[str, float]) -> "Score":
        """Build a score by summing named weighted contributions.

        Parameters
        ----------
        contributions:
            Mapping of ``contributor_name -> weighted_points``. Only the values
            matter for the total; the names are preserved by the caller for
            explainability/audit.
        """
        return cls(sum(contributions.values()))

    @property
    def normalized(self) -> float:
        """Return the score on a 0.0-1.0 scale (useful for STIX confidence)."""
        return self.value / Score.MAX
