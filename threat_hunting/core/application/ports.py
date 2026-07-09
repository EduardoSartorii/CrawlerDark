"""Application ports for hexagonal architecture.

Adapters in infrastructure implement these protocols. The core imports only
protocols, keeping business rules independent from databases, HTTP clients,
queues, MISP, OpenCTI, Redis, or CLI frameworks.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any, Protocol
from uuid import UUID

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import DomainEvent
from threat_hunting.core.domain.rules import DetectionRule, RuleMatch


class FindingRepository(Protocol):
    """Repository pattern port for finding persistence."""

    def save(self, finding: Finding) -> Finding:
        """Persist a finding and return the stored aggregate."""

    def get(self, finding_id: UUID) -> Finding | None:
        """Retrieve a finding by identifier."""

    def list(self) -> list[Finding]:
        """List persisted findings."""

    def find_by_fingerprint(self, fingerprint: str) -> Finding | None:
        """Find an existing finding by deterministic deduplication fingerprint."""


class UnitOfWork(Protocol):
    """Unit of Work boundary for transactional persistence."""

    findings: FindingRepository

    def __enter__(self) -> "UnitOfWork":
        """Open transaction scope."""

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        """Commit or rollback transaction scope."""

    def commit(self) -> None:
        """Commit pending changes."""

    def rollback(self) -> None:
        """Rollback pending changes."""


class EventBus(Protocol):
    """Observer pattern port for domain events."""

    def publish(self, event: DomainEvent) -> None:
        """Publish one event."""

    def subscribe(self, event_name: str, handler: Callable[[DomainEvent], None]) -> None:
        """Subscribe a handler to a named event."""


class DetectionEngine(Protocol):
    """Strategy port for matching configurable rules."""

    def evaluate(self, finding: Finding) -> list[RuleMatch]:
        """Evaluate configured detection rules for a finding."""


class ScoringEngine(Protocol):
    """Strategy port for turning matches and context into risk scores."""

    def score(self, finding: Finding, matches: Sequence[RuleMatch]) -> Finding:
        """Return a scored finding."""


class CorrelationEngine(Protocol):
    """Strategy port for linking related entities."""

    def correlate(self, finding: Finding, existing: Iterable[Finding]) -> Finding:
        """Return a finding enriched with relationships."""


class DeduplicationEngine(Protocol):
    """Strategy port for duplicate detection."""

    def fingerprint(self, finding: Finding) -> str:
        """Build a deterministic fingerprint."""

    def is_duplicate(self, finding: Finding, existing: Iterable[Finding]) -> bool:
        """Return whether the finding duplicates an existing record."""


class EnrichmentEngine(Protocol):
    """Strategy port for contextual enrichment."""

    def enrich(self, finding: Finding) -> Finding:
        """Return an enriched finding."""


class Exporter(Protocol):
    """Adapter port for MISP, OpenCTI, Splunk, JSON, STIX, TAXII, and webhooks."""

    name: str

    def export(self, findings: Sequence[Finding]) -> None:
        """Export one or more findings."""


class OpsecTransport(Protocol):
    """OPSEC transport abstraction used by connectors."""

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        """Perform network access under a configured OPSEC profile."""
