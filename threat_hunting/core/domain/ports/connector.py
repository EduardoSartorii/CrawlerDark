"""ConnectorPort — contrato de todo conector de fonte."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from ..entities import Finding


@runtime_checkable
class ConnectorPort(Protocol):
    """Contrato: connect / collect / parse / normalize / health / close."""

    name: str

    async def connect(self) -> None: ...

    async def collect(self) -> AsyncIterator[Any]:
        """Emite payloads brutos vindos da fonte (ainda não normalizados)."""
        ...

    async def parse(self, payload: Any) -> dict[str, Any]:
        """Converte payload bruto em dicionário estruturado."""
        ...

    async def normalize(self, parsed: dict[str, Any]) -> Finding:
        """Constrói um ``Finding`` a partir do payload estruturado."""
        ...

    async def health(self) -> bool: ...

    async def close(self) -> None: ...
