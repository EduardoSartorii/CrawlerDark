"""SchedulerPort — agendamento de jobs periódicos."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class SchedulerPort(Protocol):
    def add_job(
        self,
        job_id: str,
        func: Callable[..., Awaitable[Any]],
        *,
        trigger: str,
        **trigger_options: Any,
    ) -> None: ...

    async def start(self) -> None: ...
    async def shutdown(self) -> None: ...
    def list_jobs(self) -> list[str]: ...
