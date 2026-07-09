"""Caso de uso: rodar um conector do começo ao fim pelo pipeline."""

from __future__ import annotations

from ...domain.entities import Job
from ...domain.exceptions import ConnectorError, PipelineError
from ...domain.ports import ConnectorPort, UnitOfWorkPort
from ..pipeline import PipelineContext, PipelineOrchestrator


class RunConnectorPipelineUseCase:
    """Orquestra ``collect → pipeline`` para um conector.

    Cria um ``Job`` para rastreabilidade, iterando pelos payloads emitidos e
    processando cada um pelo pipeline. Falhas em itens individuais não
    interrompem os demais (marca job como PARTIAL).
    """

    def __init__(
        self,
        orchestrator: PipelineOrchestrator,
        uow_factory: type[UnitOfWorkPort] | object,
    ) -> None:
        self._orchestrator = orchestrator
        self._uow_factory = uow_factory

    async def execute(self, connector: ConnectorPort) -> Job:
        job = Job(connector=connector.name)
        job.mark_running()
        async with self._uow_factory() as uow:  # type: ignore[operator]
            await uow.jobs.add(job)
            await uow.commit()

        collected = 0
        persisted = 0
        errors: list[str] = []
        try:
            await connector.connect()
            async for payload in connector.collect():
                collected += 1
                context = PipelineContext(
                    connector=connector.name,
                    payload=payload,
                    connector_instance=connector,
                )
                try:
                    context = await self._orchestrator.process(context)
                except PipelineError as exc:
                    errors.append(str(exc))
                    continue
                if context.finding is not None and not context.discard:
                    persisted += 1
        except ConnectorError as exc:
            errors.append(str(exc))
        finally:
            try:
                await connector.close()
            except Exception:  # noqa: BLE001
                pass

        if errors and persisted == 0:
            job.mark_failure("; ".join(errors[:5]))
        elif errors:
            job.mark_partial("; ".join(errors[:5]), persisted, collected)
        else:
            job.mark_success(persisted, collected)

        async with self._uow_factory() as uow:  # type: ignore[operator]
            await uow.jobs.update(job)
            await uow.commit()
        return job
