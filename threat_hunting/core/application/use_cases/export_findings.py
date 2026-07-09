"""Caso de uso: exportação em lote sob demanda para um destino específico."""

from __future__ import annotations

from ...domain.ports import ExporterPort, UnitOfWorkPort


class ExportFindingsUseCase:
    """Exporta findings ainda-não-exportados para um destino, respeitando threshold."""

    def __init__(self, uow_factory: type[UnitOfWorkPort] | object) -> None:
        self._uow_factory = uow_factory

    async def execute(
        self,
        exporter: ExporterPort,
        *,
        min_score: float = 0.0,
        limit: int = 500,
    ) -> int:
        async with self._uow_factory() as uow:  # type: ignore[operator]
            findings = list(
                await uow.findings.find_unexported(
                    target=exporter.name, min_score=min_score, limit=limit
                )
            )
            if not findings:
                return 0
            exported = await exporter.export(findings)
            for f in findings[:exported]:
                f.mark_exported(exporter.name)
                await uow.findings.update(f)
            await uow.commit()
        return exported
