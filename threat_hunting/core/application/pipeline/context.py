"""Contexto compartilhado entre estágios do pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ...domain.entities import Finding
from ...domain.ports import ConnectorPort


@dataclass(slots=True)
class PipelineContext:
    """Payload mutável que atravessa o pipeline.

    * ``payload`` é o dado bruto emitido pelo conector.
    * ``finding`` é construído a partir da fase Parse/Normalize.
    * ``metadata`` guarda métricas por estágio (tempo, decisões).
    * ``duplicate_of`` sinaliza que o finding é duplicata (usado no persist).
    """

    connector: str
    payload: Any
    connector_instance: ConnectorPort | None = None
    finding: Finding | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    duplicate_of: Finding | None = None
    discard: bool = False

    def stage_meta(self, stage: str) -> dict[str, Any]:
        return self.metadata.setdefault(stage, {})
