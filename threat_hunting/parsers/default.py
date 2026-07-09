"""Default parser strategy."""

from __future__ import annotations

from typing import Any


class PassthroughParser:
    """Return dictionary payloads unchanged and wrap scalar payloads."""

    def parse(self, payload: Any) -> dict[str, Any]:
        """Parse a payload into a dictionary."""

        if isinstance(payload, dict):
            return payload
        return {"value": payload}
