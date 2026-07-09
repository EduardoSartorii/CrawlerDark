"""Severity — nível de gravidade de um ``Finding`` ou ``DetectionRule``.

Alinhado com convenções de MITRE / CVSS-like buckets. É ordenável, permitindo
comparações do tipo ``severity >= Severity.HIGH``.
"""

from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """Gravidade ordenável (INFO < LOW < MEDIUM < HIGH < CRITICAL)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str | "Severity") -> "Severity":
        """Constrói a partir de nome case-insensitive."""
        if isinstance(value, cls):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"Invalid severity: {value!r}") from exc

    def label(self) -> str:
        return self.name.title()
