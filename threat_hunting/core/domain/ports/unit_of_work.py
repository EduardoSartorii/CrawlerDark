"""UnitOfWorkPort — atomicidade transacional."""

from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self, runtime_checkable

from .repositories import (
    DetectionRuleRepositoryPort,
    FindingRepositoryPort,
    IndicatorRepositoryPort,
    JobRepositoryPort,
    ThreatActorRepositoryPort,
    WatchlistRepositoryPort,
)


@runtime_checkable
class UnitOfWorkPort(Protocol):
    findings: FindingRepositoryPort
    indicators: IndicatorRepositoryPort
    threat_actors: ThreatActorRepositoryPort
    watchlists: WatchlistRepositoryPort
    rules: DetectionRuleRepositoryPort
    jobs: JobRepositoryPort

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...
