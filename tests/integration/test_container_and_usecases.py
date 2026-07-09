"""Integration tests for the DI container, use cases and scheduler."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.application.use_cases.run_hunt import RunHuntUseCase
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import ConnectorStatus
from threat_hunting.core.domain.exceptions import ConnectorNotFoundError
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.di.container import (
    build_container,
    build_export_use_case,
    build_pipeline,
    build_run_hunt_use_case,
)
from threat_hunting.infrastructure.scheduler.aps_scheduler import HuntScheduler


def test_container_wires_full_platform(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TH_STORAGE__BACKEND", "memory")
    container = build_container(None)  # defaults + env
    assert container.registry().names()
    pipeline = build_pipeline(container)
    assert pipeline is not None
    export_uc = build_export_use_case(container)
    assert "json" in export_uc.available()
    run_uc = build_run_hunt_use_case(container)
    assert isinstance(run_uc, RunHuntUseCase)


async def test_container_run_sample_via_use_case(monkeypatch) -> None:
    monkeypatch.setenv("TH_STORAGE__BACKEND", "memory")
    monkeypatch.setenv("TH_EXPORT__AUTO_EXPORT_TARGETS", '["misp"]')
    container = build_container(None)
    use_case = build_run_hunt_use_case(container)
    result = await use_case.run_one("sample")
    assert result.collected == 3
    assert result.persisted >= 1


async def test_run_hunt_unknown_connector_raises() -> None:
    def resolver(name: str):
        raise KeyError(name)

    use_case = RunHuntUseCase(
        pipeline=None,  # type: ignore[arg-type]
        resolve_connector=resolver,
        list_connectors=lambda: [],
    )
    try:
        await use_case.run_one("ghost")
    except ConnectorNotFoundError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected ConnectorNotFoundError")


class _StubConnector(BaseConnector):
    name = "stub"
    source = "stub"

    async def connect(self) -> None:
        return None

    async def collect(self) -> Sequence[RawRecord]:
        return [self._record(content="leak dump acme", metadata={"title": "x"})]

    async def health(self) -> ConnectorStatus:
        return ConnectorStatus.HEALTHY


async def test_scheduler_runs_fixed_iterations(monkeypatch) -> None:
    ran: list[int] = []

    class _UC(RunHuntUseCase):
        def __init__(self) -> None:  # bypass base init
            pass

        async def run_all(self):  # type: ignore[override]
            from threat_hunting.core.application.dto import PipelineResult

            ran.append(1)
            return PipelineResult(connector="all", collected=1)

    scheduler = HuntScheduler(use_case=_UC(), interval_seconds=0)
    await scheduler.run(iterations=2)
    assert len(ran) == 2
