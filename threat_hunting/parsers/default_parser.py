"""Default parser strategy used by connectors without custom parser."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any


class DefaultParser:
    """Lightweight parser that keeps records normalized as dictionaries."""

    def process(self, raw_items: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        """Return a copy to avoid mutating connector raw payload in place."""
        return [dict(item) for item in raw_items]
