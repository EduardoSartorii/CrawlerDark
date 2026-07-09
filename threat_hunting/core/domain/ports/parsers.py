"""Ports para parser, extractor e normalizer (usados dentro do pipeline)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..entities import Finding


@runtime_checkable
class ParserPort(Protocol):
    async def parse(self, payload: Any) -> dict[str, Any]: ...


@runtime_checkable
class ExtractorPort(Protocol):
    async def extract(self, finding: Finding) -> Finding:
        """Extrai IOCs, credenciais, cartões, etc. e anexa ao finding."""
        ...


@runtime_checkable
class NormalizerPort(Protocol):
    async def normalize(self, finding: Finding) -> Finding: ...
