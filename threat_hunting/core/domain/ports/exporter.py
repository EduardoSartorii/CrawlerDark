"""ExporterPort — adapter para sistemas externos (MISP, OpenCTI, ...)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from ..entities import Finding


@runtime_checkable
class ExporterPort(Protocol):
    """Todo exporter herda esse contrato."""

    name: str

    async def export(self, findings: Sequence[Finding]) -> int:
        """Exporta findings. Retorna a quantidade exportada com sucesso."""
        ...

    async def health(self) -> bool: ...
