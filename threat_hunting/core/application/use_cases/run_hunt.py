"""``RunHuntUseCase`` — collect from one, several or all connectors.

Responsibility
--------------
Coordinate a hunting run: resolve the requested connector(s) from the registry,
execute the pipeline for each and aggregate the results. This is the use case
the CLI (`hunt run ...`) and the scheduler invoke. It contains no source- or
storage-specific logic — only orchestration.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from threat_hunting.core.application.dto import PipelineResult
from threat_hunting.core.application.pipeline import Pipeline
from threat_hunting.core.application.ports.connector import ConnectorPort
from threat_hunting.core.domain.exceptions import ConnectorNotFoundError

#: A resolver maps a connector name to an instance (provided by the registry).
ConnectorResolver = Callable[[str], ConnectorPort]
#: Lists the names of all enabled connectors.
ConnectorLister = Callable[[], list[str]]


class RunHuntUseCase:
    """Runs the collection pipeline for the requested connectors."""

    def __init__(
        self,
        *,
        pipeline: Pipeline,
        resolve_connector: ConnectorResolver,
        list_connectors: ConnectorLister,
    ) -> None:
        self._pipeline = pipeline
        self._resolve = resolve_connector
        self._list = list_connectors

    async def run_one(self, name: str) -> PipelineResult:
        """Run the pipeline for a single connector by name."""
        try:
            connector = self._resolve(name)
        except KeyError as exc:  # registry raises KeyError for unknown names
            raise ConnectorNotFoundError(name) from exc
        return await self._pipeline.run(connector)

    async def run_many(self, names: Iterable[str]) -> PipelineResult:
        """Run the pipeline for several connectors and aggregate results."""
        aggregate = PipelineResult(connector="multi")
        for name in names:
            aggregate.merge(await self.run_one(name))
        return aggregate

    async def run_all(self) -> PipelineResult:
        """Run every enabled connector."""
        return await self.run_many(self._list())
