"""Contrato base de um estágio do pipeline (Chain of Responsibility)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from .context import PipelineContext


class PipelineStage(ABC):
    """Cada estágio recebe e devolve o contexto (possivelmente mutado).

    Implementações devem ser idempotentes e não devem levantar exceções
    para casos esperados — usar ``context.discard = True`` ou registrar
    metadados. Exceções não tratadas são propagadas ao ``PipelineOrchestrator``.
    """

    name: str = "stage"

    @abstractmethod
    async def run(self, context: PipelineContext) -> PipelineContext: ...
