"""Default parser stage implementation."""

from __future__ import annotations

from threat_hunting.core.contracts import StageContext


class DefaultParser:
    """Parser that normalizes text fields and strips invalid values."""

    def run(self, items: list[dict[str, object]], context: StageContext) -> list[dict[str, object]]:
        """Run parser stage."""
        parsed: list[dict[str, object]] = []
        for item in items:
            parsed.append(
                {
                    **item,
                    "title": str(item.get("title", "")).strip(),
                    "description": str(item.get("description", "")).strip(),
                }
            )
        return parsed
