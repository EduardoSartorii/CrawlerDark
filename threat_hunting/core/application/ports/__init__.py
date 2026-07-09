"""Application-layer ports (Hexagonal).

Responsibility
--------------
Define contracts used by use cases and the pipeline. Implementations live
in infrastructure/, connectors/, detections/, scoring/, etc.
Core never imports concrete adapters.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Sequence
from typing import Any, Protocol, runtime_checkable

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import ExportFormat, HealthState
from threat_hunting.core.domain.events import DomainEvent
from threat_hunting.core.domain.value_objects import (
    DetectionMatch,
    HealthStatus,
    OpsecProfile,
)


# ---------------------------------------------------------------------------
# Collection documents (pipeline intermediate types)
# ---------------------------------------------------------------------------


class RawDocument(dict[str, Any]):
    """Opaque raw payload collected from a source."""


class ParsedDocument(dict[str, Any]):
    """Structured document after parsing."""


class ExtractedEntities(dict[str, Any]):
    """Entities extracted from a parsed document (IOCs, emails, etc.)."""


# ---------------------------------------------------------------------------
# Connector Port (Template Method contract)
# ---------------------------------------------------------------------------


class ConnectorPort(ABC):
    """Port every connector must satisfy.

    Template Method flow: connect → collect → parse → normalize → close.
    Plugin Pattern: discovered via ConnectorRegistry; Core never modified.
    """

    name: str
    category_group: str

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection / authenticate."""

    @abstractmethod
    def collect(self) -> AsyncIterator[RawDocument]:
        """Yield raw documents from the source."""

    @abstractmethod
    async def parse(self, raw: RawDocument) -> ParsedDocument:
        """Parse a raw document into structured form."""

    @abstractmethod
    async def normalize(self, parsed: ParsedDocument) -> Finding:
        """Normalize into canonical Finding aggregate."""

    @abstractmethod
    async def health(self) -> HealthStatus:
        """Report connector health."""

    @abstractmethod
    async def close(self) -> None:
        """Release resources."""


class ConnectorFactoryPort(ABC):
    """Factory Pattern — resolve connectors by name."""

    @abstractmethod
    def create(self, name: str, **options: Any) -> ConnectorPort: ...

    @abstractmethod
    def list_available(self) -> Sequence[str]: ...

    @abstractmethod
    def list_by_group(self, group: str) -> Sequence[str]: ...


# ---------------------------------------------------------------------------
# Pipeline stage ports (Strategy Pattern)
# ---------------------------------------------------------------------------


class ParserPort(ABC):
    @abstractmethod
    async def parse(self, raw: RawDocument, *, connector: str) -> ParsedDocument: ...


class ExtractorPort(ABC):
    @abstractmethod
    async def extract(self, parsed: ParsedDocument) -> ExtractedEntities: ...


class NormalizerPort(ABC):
    @abstractmethod
    async def normalize(
        self,
        parsed: ParsedDocument,
        extracted: ExtractedEntities,
        *,
        connector: str,
        source: str,
    ) -> Finding: ...


class DetectionEnginePort(ABC):
    """Detection Engine — Strategy registry of dynamic rules."""

    @abstractmethod
    async def detect(self, finding: Finding) -> list[DetectionMatch]: ...

    @abstractmethod
    async def reload_rules(self) -> int:
        """Reload rules from config; returns count loaded."""


class ScoringEnginePort(ABC):
    """Scoring Engine — configurable weighted scoring."""

    @abstractmethod
    async def score(self, finding: Finding) -> Finding: ...


class CorrelationEnginePort(ABC):
    """Correlation Engine — link related entities across findings."""

    @abstractmethod
    async def correlate(self, finding: Finding) -> Finding: ...


class DeduplicationEnginePort(ABC):
    """Deduplication Engine — hash / similarity / IOC based."""

    @abstractmethod
    async def deduplicate(self, finding: Finding) -> Finding: ...


class EnrichmentEnginePort(ABC):
    """Enrichment Engine — external reputation / context."""

    @abstractmethod
    async def enrich(self, finding: Finding) -> Finding: ...


# ---------------------------------------------------------------------------
# OPSEC
# ---------------------------------------------------------------------------


class OpsecTransportPort(ABC):
    """Abstract network transport with OPSEC controls."""

    @abstractmethod
    async def get(
        self, url: str, *, profile: OpsecProfile, **kwargs: Any
    ) -> Any: ...

    @abstractmethod
    async def post(
        self, url: str, *, profile: OpsecProfile, **kwargs: Any
    ) -> Any: ...

    @abstractmethod
    async def request(
        self, method: str, url: str, *, profile: OpsecProfile, **kwargs: Any
    ) -> Any: ...


class CredentialVaultPort(ABC):
    @abstractmethod
    async def get(self, ref: str) -> dict[str, str]: ...


class RateLimiterPort(ABC):
    @abstractmethod
    async def acquire(self, key: str, *, rps: float) -> None: ...


# ---------------------------------------------------------------------------
# Storage / Export
# ---------------------------------------------------------------------------


class StorageBackendPort(ABC):
    """Abstract storage backend — swap without changing business rules."""

    name: str

    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def persist_finding(self, finding: Finding) -> None: ...

    @abstractmethod
    async def fetch_finding(self, finding_id: str) -> Finding | None: ...

    @abstractmethod
    async def query_findings(self, **filters: Any) -> Sequence[Finding]: ...

    @abstractmethod
    async def health(self) -> HealthStatus: ...

    @abstractmethod
    async def close(self) -> None: ...


class ExporterPort(ABC):
    """Independent exporter adapter."""

    format: ExportFormat

    @abstractmethod
    async def export(self, findings: Sequence[Finding], **options: Any) -> dict[str, Any]: ...

    @abstractmethod
    async def health(self) -> HealthStatus: ...


class ExporterFactoryPort(ABC):
    @abstractmethod
    def create(self, format_name: str) -> ExporterPort: ...

    @abstractmethod
    def list_available(self) -> Sequence[str]: ...


# ---------------------------------------------------------------------------
# Events / Observability / Audit
# ---------------------------------------------------------------------------


@runtime_checkable
class EventHandler(Protocol):
    async def handle(self, event: DomainEvent) -> None: ...


class EventBusPort(ABC):
    """Observer Pattern — publish/subscribe domain events."""

    @abstractmethod
    def subscribe(self, event_type: str, handler: EventHandler) -> None: ...

    @abstractmethod
    async def publish(self, event: DomainEvent) -> None: ...

    @abstractmethod
    async def publish_many(self, events: Sequence[DomainEvent]) -> None: ...


class MetricsPort(ABC):
    @abstractmethod
    def incr(self, name: str, *, value: float = 1.0, labels: dict[str, str] | None = None) -> None: ...

    @abstractmethod
    def observe(self, name: str, value: float, *, labels: dict[str, str] | None = None) -> None: ...

    @abstractmethod
    def gauge(self, name: str, value: float, *, labels: dict[str, str] | None = None) -> None: ...


class TracerPort(ABC):
    @abstractmethod
    def start_span(self, name: str, **attrs: Any) -> Any: ...


class AuditPort(ABC):
    @abstractmethod
    async def record(
        self, action: str, *, actor: str = "system", details: dict[str, Any] | None = None
    ) -> None: ...


class HealthCheckPort(ABC):
    @abstractmethod
    async def check_all(self) -> list[HealthStatus]: ...

    @abstractmethod
    async def overall(self) -> HealthState: ...


class UnitOfWorkPort(ABC):
    """Unit of Work — atomic multi-repository transactions."""

    findings: Any  # FindingRepositoryPort
    watchlists: Any
    threat_actors: Any
    campaigns: Any
    hunt_jobs: Any
    connectors: Any

    @abstractmethod
    async def __aenter__(self) -> UnitOfWorkPort: ...

    @abstractmethod
    async def __aexit__(self, *exc: Any) -> None: ...

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...


__all__ = [
    "RawDocument",
    "ParsedDocument",
    "ExtractedEntities",
    "ConnectorPort",
    "ConnectorFactoryPort",
    "ParserPort",
    "ExtractorPort",
    "NormalizerPort",
    "DetectionEnginePort",
    "ScoringEnginePort",
    "CorrelationEnginePort",
    "DeduplicationEnginePort",
    "EnrichmentEnginePort",
    "OpsecTransportPort",
    "CredentialVaultPort",
    "RateLimiterPort",
    "StorageBackendPort",
    "ExporterPort",
    "ExporterFactoryPort",
    "EventHandler",
    "EventBusPort",
    "MetricsPort",
    "TracerPort",
    "AuditPort",
    "HealthCheckPort",
    "UnitOfWorkPort",
]
