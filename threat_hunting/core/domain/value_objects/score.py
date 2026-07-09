"""Score and DetectionMatch value objects.

Responsibility
--------------
* :class:`DetectionMatch` records *why* a detection fired (rule id, matched
  text, contribution). It is the audit trail behind a score.
* :class:`Score` is the aggregate numeric assessment of a finding, always in
  the ``0..100`` range, together with the breakdown of the matches and weights
  that produced it. Keeping the breakdown makes scoring explainable, which is a
  hard requirement for analyst trust.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class DetectionMatch(BaseModel):
    """A single rule match contributing to detection/scoring."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_type: str = Field(description="regex | keyword | ioc | yara | sigma | heuristic")
    matched: str = Field(description="The text/value that matched.")
    weight: float = Field(default=0.0, description="Weight contribution to the score.")
    category: str | None = None


class Score(BaseModel):
    """Explainable numeric assessment of a finding (0-100)."""

    model_config = ConfigDict(frozen=True)

    value: float = Field(default=0.0, ge=0.0, le=100.0)
    breakdown: dict[str, float] = Field(
        default_factory=dict,
        description="Per-component contribution (component name -> points).",
    )

    @classmethod
    def zero(cls) -> "Score":
        """Return an empty/neutral score."""
        return cls(value=0.0, breakdown={})

    def with_component(self, name: str, points: float) -> "Score":
        """Return a new score with ``points`` added under ``name`` (clamped to 100)."""
        merged = dict(self.breakdown)
        merged[name] = merged.get(name, 0.0) + points
        total = min(100.0, max(0.0, sum(merged.values())))
        return Score(value=total, breakdown=merged)
