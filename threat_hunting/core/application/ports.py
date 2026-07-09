"""Ports consumed by application services.

Infrastructure adapters implement these protocols. This inversion keeps the
core isolated from SQLAlchemy, httpx, Redis, PyMISP, Typer and scheduler details.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any, Protocol

from threat_hunting.core.domain.entities import ConnectorDefinition, DetectionRule, Finding
from threat_hunting.core.domain.events import DomainEvent


class BaseConnector(Protocol):
    """Connector SDK contract required for every collection plugin."""

    name: str
    source: str

    def connect(self) -> None:
        """Initialize network sessions, clients or authentication."""

    def collect(self) -> Iterable[Any]:
        """Collect raw records from the source."""

    def parse(self, raw_item: Any) -> dict[str, Any]:
        """Parse raw source records into dictionaries."""

    def normalize(self, parsed_item: dict[str, Any]) -> Finding:
        """Normalize parsed records into the canonical finding model."""

    def health(self) -> dict[str, Any]:
        """Return connector health details."""

    def close(self) -> None:
        """Release network sessions and other external resources."""


class ParserPort(Protocol):
    """Transform raw payloads into structured records."""

    def parse(self, payload: Any) -> dict[str, Any]:
        """Parse a raw payload."""


class ExtractorPort(Protocol):
    """Extract indicators, artifacts and entities from findings."""

    def extract(self, finding: Finding) -> Finding:
        """Return a finding enriched with extracted entities."""


class NormalizerPort(Protocol):
    """Normalize source-specific fields into canonical values."""

    def normalize(self, finding: Finding) -> Finding:
        """Return a normalized finding."""


class DetectionEnginePort(Protocol):
    """Apply dynamic rules to findings."""

    def detect(self, finding: Finding) -> Finding:
        """Return a finding with detection metadata and tags."""


class ScoringEnginePort(Protocol):
    """Calculate configurable business risk score."""

    def score(self, finding: Finding) -> Finding:
        """Return a scored finding."""


class CorrelationEnginePort(Protocol):
    """Create relationships across findings and indicators."""

    def correlate(self, finding: Finding, existing: Sequence[Finding]) -> Finding:
        """Return a finding with correlation relationships."""


class DeduplicationEnginePort(Protocol):
    """Detect whether a finding already exists."""

    def is_duplicate(self, finding: Finding, existing: Sequence[Finding]) -> bool:
        """Return true when the finding should not be persisted again."""


class EnrichmentEnginePort(Protocol):
    """Enrich findings with external or derived context."""

    def enrich(self, finding: Finding) -> Finding:
        """Return an enriched finding."""


class FindingRepository(Protocol):
    """Persistence contract for canonical findings."""

    def add(self, finding: Finding) -> None:
        """Persist a finding."""

    def list(self) -> list[Finding]:
        """Return known findings."""

    def get_by_hash(self, content_hash: str) -> Finding | None:
        """Return a finding by stable content hash."""


class DetectionRuleRepository(Protocol):
    """Repository for dynamic detection rules."""

    def list_enabled(self) -> list[DetectionRule]:
        """Return enabled rules."""


class UnitOfWork(Protocol):
    """Transaction boundary for application services."""

    findings: FindingRepository

    def __enter__(self) -> "UnitOfWork":
        """Open a transaction scope."""

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Commit or roll back the transaction scope."""

    def commit(self) -> None:
        """Commit pending changes."""

    def rollback(self) -> None:
        """Rollback pending changes."""


class ExporterPort(Protocol):
    """Independent exporter contract for MISP, STIX, CSV and SIEM adapters."""

    name: str

    def export(self, finding: Finding) -> None:
        """Export a finding."""


class EventBus(Protocol):
    """Observer pattern contract for domain events."""

    def publish(self, event: DomainEvent) -> None:
        """Publish an event to observers."""


class ConnectorRegistryPort(Protocol):
    """Registry used by commands and schedulers to discover connectors."""

    def discover(self) -> None:
        """Load configured and plugin-provided connectors."""

    def get(self, name: str) -> BaseConnector:
        """Return one connector by name."""

    def list(self, enabled_only: bool = True) -> list[ConnectorDefinition]:
        """List connector definitions."""
