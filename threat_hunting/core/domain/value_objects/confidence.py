"""Confidence — inteiro 0..100 representando confiança da detecção."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True, order=True)
class Confidence:
    """Confiança 0..100."""

    value: int

    def __post_init__(self) -> None:
        if not isinstance(self.value, int):
            raise TypeError(f"Confidence must be int, got {type(self.value).__name__}")
        if not 0 <= self.value <= 100:
            raise ValueError(f"Confidence must be within 0..100, got {self.value}")

    @classmethod
    def low(cls) -> "Confidence":
        return cls(25)

    @classmethod
    def medium(cls) -> "Confidence":
        return cls(50)

    @classmethod
    def high(cls) -> "Confidence":
        return cls(85)

    def __int__(self) -> int:
        return self.value
