"""Score — pontuação normalizada 0.0..100.0 atribuída pelo Scoring Engine."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class Score:
    """Pontuação float 0..100 (clamp aplicado no construtor)."""

    value: float

    def __post_init__(self) -> None:
        if not isinstance(self.value, (int, float)):
            raise TypeError(f"Score must be numeric, got {type(self.value).__name__}")
        clamped = max(0.0, min(100.0, float(self.value)))
        object.__setattr__(self, "value", clamped)

    @classmethod
    def zero(cls) -> "Score":
        return cls(0.0)

    def __float__(self) -> float:
        return self.value
