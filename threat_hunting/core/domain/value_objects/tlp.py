"""Traffic Light Protocol — nível de compartilhamento permitido."""

from __future__ import annotations

from enum import Enum


class TLP(str, Enum):
    WHITE = "WHITE"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"

    @classmethod
    def coerce(cls, value: str | "TLP" | None) -> "TLP":
        if value is None:
            return cls.AMBER
        if isinstance(value, cls):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            return cls.AMBER
