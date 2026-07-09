"""JSONParser — auxiliar para conectores que consomem APIs."""

from __future__ import annotations

import json
from typing import Any


class JSONParser:
    async def parse(self, payload: str | bytes | dict[str, Any] | list[Any]) -> Any:
        if isinstance(payload, (dict, list)):
            return payload
        return json.loads(payload)
