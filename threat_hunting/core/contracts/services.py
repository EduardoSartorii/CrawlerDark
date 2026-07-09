"""Service port interfaces for pipeline stages and infrastructure adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities import Finding, FindingDraft
    from threat_hunting.core.domain.enums import HealthStatus
    from threat_hunting.core.domain.events import DomainEvent


class RawPayload:
    """Opaque raw data container from connector collection."""

    def __init__(self, data: dict[str, Any], source_uri: str = "", metadata: dict[str, Any] | None = None):
        self.data = data
        self.source_uri = source_uri
        self.metadata = metadata or {}


class ParsedData:
    """Structured data after parsing stage."""

    def __init__(self, fields: dict[str, Any], content: str = "", metadata: dict[str, Any] | None = None):
        self.fields = fields
        self.content = content
        self.metadata = metadata or {}


class ExtractedData:
    """Data after extraction stage with entities and indicators."""

    def __init__(
        self,
        parsed: ParsedData,
        indicators: list[dict[str, Any]] | None = None,
        entities: dict[str, Any] | None = None,
    ):
        self.parsed = parsed
        self.indicators = indicators or []
        self.entities = entities or {}


class CollectionContext:
    """Runtime context passed to connectors during collection."""

    def __init__(
        self,
        connector_name: str,
        keywords: list[str] | None = None,
        watchlists: dict[str, list[str]] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.connector_name = connector_name
        self.keywords = keywords or []
        self.watchlists = watchlists or {}
        self.metadata = metadata or {}


class IConnector(ABC):
    """Base connector port — all connectors must implement this contract."""

    name: str
    source_type: str

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to data source."""

    @abstractmethod
    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        """Collect raw payloads from source."""
        yield RawPayload({})  # pragma: no cover

    @abstractmethod
    def parse(self, payload: RawPayload) -> ParsedData:
        """Parse raw payload into structured data."""

    @abstractmethod
    def normalize(self, parsed: ParsedData) -> FindingDraft:
        """Normalize parsed data into a finding draft."""

    @abstractmethod
    async def health(self) -> HealthStatus:
        """Report connector health status."""

    @abstractmethod
    async def close(self) -> None:
        """Release resources."""


class IParser(ABC):
    """Parser port for transforming raw payloads."""

    @abstractmethod
    def parse(self, payload: RawPayload) -> ParsedData:
        """Parse raw payload."""


class IExtractor(ABC):
    """Extractor port for entity and IOC extraction."""

    @abstractmethod
    def extract(self, parsed: ParsedData) -> ExtractedData:
        """Extract indicators and entities from parsed data."""


class INormalizer(ABC):
    """Normalizer port for producing Finding drafts."""

    @abstractmethod
    def normalize(self, extracted: ExtractedData, connector: str, source_type: str) -> FindingDraft:
        """Normalize extracted data into finding draft."""


class IDetectionEngine(ABC):
    """Detection engine port — applies dynamic rules."""

    @abstractmethod
    async def detect(self, finding: Finding) -> tuple[Finding, list[str]]:
        """Apply detection rules; returns enriched finding and matched rule names."""


class IScoringEngine(ABC):
    """Scoring engine port — calculates risk score."""

    @abstractmethod
    async def score(self, finding: Finding) -> Finding:
        """Calculate and assign score to finding."""


class ICorrelationEngine(ABC):
    """Correlation engine port — links related entities."""

    @abstractmethod
    async def correlate(self, finding: Finding) -> tuple[Finding, list[dict[str, Any]]]:
        """Correlate finding with existing intelligence."""


class IDeduplicationEngine(ABC):
    """Deduplication engine port — eliminates duplicates."""

    @abstractmethod
    async def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Filter duplicate findings."""


class IEnrichmentEngine(ABC):
    """Enrichment engine port — enriches via external APIs."""

    @abstractmethod
    async def enrich(self, finding: Finding) -> Finding:
        """Enrich finding with external intelligence."""


class IStorageBackend(ABC):
    """Abstract storage backend — swappable without business logic changes."""

    @abstractmethod
    async def save_finding(self, finding: Finding) -> Finding:
        """Persist a finding."""

    @abstractmethod
    async def get_finding(self, finding_id: str) -> Finding | None:
        """Retrieve finding by ID."""

    @abstractmethod
    async def list_findings(self, limit: int = 100) -> list[Finding]:
        """List stored findings."""

    @abstractmethod
    async def health(self) -> HealthStatus:
        """Check storage backend health."""


class IExporter(ABC):
    """Abstract exporter for external integrations."""

    name: str

    @abstractmethod
    async def export(self, findings: list[Finding]) -> dict[str, Any]:
        """Export findings to external destination."""

    @abstractmethod
    async def health(self) -> HealthStatus:
        """Check exporter connectivity."""


class IOpsecTransport(ABC):
    """OPSEC transport port — abstracts network layer with security controls."""

    @abstractmethod
    async def get(self, url: str, **kwargs: Any) -> Any:
        """Perform GET request with OPSEC profile."""

    @abstractmethod
    async def post(self, url: str, **kwargs: Any) -> Any:
        """Perform POST request with OPSEC profile."""

    @abstractmethod
    async def close(self) -> None:
        """Close transport resources."""


class IEventBus(ABC):
    """Event bus port for observer pattern."""

    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        """Publish domain event to subscribers."""

    @abstractmethod
    def subscribe(self, event_type: str, handler: Any) -> None:
        """Register event handler."""
