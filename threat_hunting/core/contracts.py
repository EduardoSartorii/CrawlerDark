"""Core ports (interfaces) for the threat hunting platform.

The core defines stable contracts and does not depend on infrastructure details.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(slots=True)
class StageContext:
    """Pipeline context shared across all stages."""

    connector_name: str
    run_id: str
    started_at: datetime
    metadata: dict[str, Any]


class ConnectorPort(ABC):
    """Connector SDK contract for every data source implementation."""

    name: str
    category: str

    @abstractmethod
    def connect(self) -> None:
        """Establish connector dependencies."""

    @abstractmethod
    def collect(self, context: StageContext) -> list[dict[str, Any]]:
        """Collect raw records from a source."""

    @abstractmethod
    def parse(self, raw_items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Parse collected records."""

    @abstractmethod
    def normalize(
        self,
        parsed_items: list[dict[str, Any]],
        context: StageContext,
    ) -> list[dict[str, Any]]:
        """Normalize parsed records into canonical schema fragments."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return connector health diagnostics."""

    @abstractmethod
    def close(self) -> None:
        """Release network/session resources."""


class ParserPort(Protocol):
    """Parser stage contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Transform raw records into parsed records."""


class ExtractorPort(Protocol):
    """Extractor stage contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Extract structured evidence from parsed records."""


class NormalizerPort(Protocol):
    """Normalizer stage contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Normalize records into canonical Finding fields."""


class DetectionEnginePort(Protocol):
    """Detection engine contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Evaluate dynamic rules and annotate matched signals."""


class ScoringEnginePort(Protocol):
    """Scoring engine contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Calculate configurable score and confidence per finding."""


class CorrelationEnginePort(Protocol):
    """Correlation engine contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Correlate findings by shared infrastructure/entities."""


class DeduplicationEnginePort(Protocol):
    """Deduplication engine contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Drop duplicated findings based on deterministic strategy."""


class EnrichmentEnginePort(Protocol):
    """Enrichment engine contract."""

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Enrich findings with external and contextual intelligence."""


class FindingRepositoryPort(Protocol):
    """Repository contract for canonical findings persistence."""

    def add_many(self, findings: Iterable["FindingLike"]) -> None:
        """Persist a list of findings."""

    def list_recent(self, limit: int = 100) -> list["FindingLike"]:
        """Return recent findings."""


class UnitOfWorkPort(Protocol):
    """Transaction boundary contract."""

    findings: FindingRepositoryPort

    def __enter__(self) -> "UnitOfWorkPort":
        """Enter transaction scope."""

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit transaction scope."""

    def commit(self) -> None:
        """Commit transaction."""

    def rollback(self) -> None:
        """Rollback transaction."""


class ExporterPort(Protocol):
    """Exporter contract for intelligence distribution channels."""

    name: str

    def export(self, findings: list["FindingLike"], context: StageContext) -> None:
        """Export findings to external sink."""


class EventBusPort(Protocol):
    """Observer/event bus contract for event-driven architecture."""

    def publish(self, event: "DomainEvent") -> None:
        """Publish an event."""

    def subscribe(self, event_type: type["DomainEvent"], handler: "EventHandler") -> None:
        """Subscribe handler to event type."""


class EventHandler(Protocol):
    """Event handler callable protocol."""

    def __call__(self, event: "DomainEvent") -> None:
        """Handle event."""


class PluginPort(Protocol):
    """Plugin contract used by discovery subsystem."""

    plugin_name: str

    def register(self) -> None:
        """Register plugin capabilities in runtime registries."""


class StoragePort(Protocol):
    """Storage backend contract (db/search/lake/file/object store)."""

    backend_name: str

    def write_findings(self, findings: list["FindingLike"]) -> None:
        """Write findings to backend."""


class TransportPort(Protocol):
    """OPSEC transport abstraction for HTTP clients and proxy behavior."""

    def get(self, url: str, *, profile: str | None = None, headers: dict[str, str] | None = None) -> Any:
        """GET request through OPSEC profile."""

    def post(
        self,
        url: str,
        *,
        profile: str | None = None,
        headers: dict[str, str] | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> Any:
        """POST request through OPSEC profile."""


class FindingLike(Protocol):
    """Structural type for canonical Finding entity."""

    id: str
    score: float
    connector: str
