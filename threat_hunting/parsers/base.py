"""Parser contracts for source-specific payloads."""

from __future__ import annotations

from typing import Any, Protocol


class Parser(Protocol):
    """Parser strategy used between connector collection and extraction."""

    def parse(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Return structured data from a raw payload."""
