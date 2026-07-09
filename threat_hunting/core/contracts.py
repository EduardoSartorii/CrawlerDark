"""Hexagonal ports and core abstractions for the platform."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from contextlib import AbstractContextManager
from typing import Any, Protocol

from threat_hunting.core.events import DomainEvent
from threat_hunting.domain.entities import ExecutionContext, Finding
from threat_hunting.domain.rules import DetectionRule


class ConnectorPort(ABC):
    """Collects data from one source and converts to canonical findings."""

    name: str

    @abstractmethod
    def connect(self) -> None:
        """Initialize external session resources."""

    @abstractmethod
    def collect(self, context: ExecutionContext) -> Sequence[dict[str, Any]]:
        """Collect raw events from the source."""

    @abstractmethod
    def parse(self, raw_items: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        """Parse raw items into structured intermediate items."""

    @abstractmethod
    def normalize(self, parsed_items: Sequence[dict[str, Any]]) -> Sequence[Finding]:
        """Normalize parsed items into canonical findings."""

    @abstractmethod
    def health(self) -> bool:
        """Report connector health state."""

    @abstractmethod
    def close(self) -> None:
        """Release connector resources."""


class ParserPort(Protocol):
    """Transforms raw connector payload into parseable records."""

    def process(self, raw_items: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        """Parse source records."""


class ExtractorPort(Protocol):
    """Extracts indicators and artifacts from parsed items."""

    def process(self, parsed_items: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        """Extract fields and potential observables."""


class NormalizerPort(Protocol):
    """Creates canonical findings from extracted items."""

    def process(
        self,
        extracted_items: Sequence[dict[str, Any]],
        connector_name: str,
    ) -> Sequence[Finding]:
        """Build findings with stable schema."""


class DetectionEnginePort(Protocol):
    """Applies dynamic rules over canonical findings."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Attach detection metadata and tags."""


class ScoringEnginePort(Protocol):
    """Calculates configurable score/confidence for findings."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Compute score based on weighted factors."""


class CorrelationEnginePort(Protocol):
    """Finds graph relationships among findings."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Attach correlation relationships."""


class DeduplicationEnginePort(Protocol):
    """Removes duplicates using content and indicator similarity."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Return deduplicated findings."""


class EnrichmentEnginePort(Protocol):
    """Adds external or internal context to findings."""

    def process(self, findings: Sequence[Finding], context: ExecutionContext) -> Sequence[Finding]:
        """Attach enrichment metadata."""


class FindingRepositoryPort(Protocol):
    """Persistence abstraction for findings."""

    def save_many(self, findings: Sequence[Finding]) -> None:
        """Persist findings collection."""

    def list_all(self) -> Sequence[Finding]:
        """Return all persisted findings."""


class RuleRepositoryPort(Protocol):
    """Dynamic repository for detection rules."""

    def load_detection_rules(self) -> Sequence[DetectionRule]:
        """Load active rules from backend."""


class UnitOfWorkPort(AbstractContextManager["UnitOfWorkPort"], Protocol):
    """Transactional boundary that wraps repository operations."""

    findings: FindingRepositoryPort

    def __enter__(self) -> UnitOfWorkPort:
        """Enter transactional context."""

    def commit(self) -> None:
        """Commit changes."""

    def rollback(self) -> None:
        """Rollback changes."""


class ExporterPort(Protocol):
    """Outbound adapter that exports findings to external destinations."""

    name: str

    def export(self, findings: Sequence[Finding], context: ExecutionContext) -> None:
        """Push findings to downstream system."""


class EventBusPort(Protocol):
    """Observer dispatcher for domain events."""

    def publish(self, event: DomainEvent) -> None:
        """Publish one event."""

    def subscribe(self, event_name: str, callback: EventHandler) -> None:
        """Register an observer for a given event."""


class EventHandler(Protocol):
    """Callable signature for event observers."""

    def __call__(self, event: DomainEvent) -> None:
        """Handle domain event."""


class MetricsPort(Protocol):
    """Metrics abstraction to keep core independent from Prometheus details."""

    def increment(self, metric: str, value: int = 1) -> None:
        """Increment a counter metric."""

    def observe(self, metric: str, value: float) -> None:
        """Observe a histogram/gauge metric value."""


class TracerPort(Protocol):
    """Tracing abstraction for OpenTelemetry integration."""

    def start_span(self, name: str) -> SpanPort:
        """Start a span context."""


class SpanPort(Protocol):
    """Span abstraction to avoid binding core to concrete SDK types."""

    def set_attribute(self, key: str, value: Any) -> None:
        """Set span attribute."""

    def __enter__(self) -> SpanPort:
        """Enter context manager."""

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """Exit context manager."""


class AuditPort(Protocol):
    """Audit sink abstraction."""

    def log(self, action: str, metadata: dict[str, Any]) -> None:
        """Store audit trail event."""


class OpsecTransportPort(Protocol):
    """Centralized transport abstraction with OPSEC controls."""

    def get(self, url: str, profile_name: str, **kwargs: Any) -> Any:
        """Perform a GET request through configured profile."""


class CredentialProviderPort(Protocol):
    """Credential lookup abstraction."""

    def get_secret(self, name: str) -> str:
        """Resolve secret from secure backend."""


class ConnectorRegistryPort(Protocol):
    """Registry contract for dynamic connector discovery."""

    def register(self, connector_type: type[ConnectorPort]) -> None:
        """Register connector type."""

    def get(self, name: str) -> ConnectorPort:
        """Instantiate connector by name."""

    def names(self) -> Iterable[str]:
        """List registered connector names."""
