"""
BaseConnector — The Foundation of the Collection SDK.

Every data source integration inherits from BaseConnector.
This abstract class enforces the collection contract that the pipeline depends on.

Design Principles:
    - Template Method Pattern: fixed skeleton, customizable steps
    - Strategy Pattern: each connector is a pluggable strategy
    - OPSEC is injected, never constructed by the connector
    - Findings are the only output — connectors never touch storage directly
    - Health checks enable monitoring and graceful degradation

Connector Lifecycle:
    1. connect()      — establish connection, authenticate
    2. collect()      — fetch raw data from source
    3. parse()        — extract structured data from raw
    4. normalize()    — produce domain Finding objects
    5. close()        — cleanup connections, release resources
    6. health()       — liveness/readiness check

Auto-Discovery:
    The plugin registry scans for BaseConnector subclasses automatically.
    No manual registration needed — just create the class and it's found.
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, AsyncIterator

import structlog

from ...core.domain.entities.finding import Finding
from ...core.domain.value_objects.source_type import SourceType
from ..opsec.http_client import OpsecHttpClient
from ..opsec.profiles import OpsecProfile

logger = structlog.get_logger(__name__)


class ConnectorStatus(StrEnum):
    """Runtime status of a connector instance."""

    IDLE = "idle"
    CONNECTING = "connecting"
    COLLECTING = "collecting"
    PARSING = "parsing"
    NORMALIZING = "normalizing"
    COMPLETED = "completed"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class ConnectorHealth:
    """Result of a connector health check."""

    connector_id: str
    healthy: bool
    status: ConnectorStatus
    last_run: datetime | None = None
    last_error: str | None = None
    findings_total: int = 0
    uptime_seconds: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectionContext:
    """
    Context object passed through the collection pipeline stages.
    Carries state between connect → collect → parse → normalize.
    """

    connector_id: str
    run_id: str
    started_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    raw_items: list[Any] = field(default_factory=list)
    parsed_items: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False

    @property
    def duration_seconds(self) -> float:
        return (datetime.now(tz=timezone.utc) - self.started_at).total_seconds()


class BaseConnector(ABC):
    """
    Abstract base class for all threat intelligence connectors.

    Subclasses MUST implement:
        - connector_id: class-level unique identifier
        - source_type: the SourceType this connector collects from
        - connect(), collect(), parse(), normalize(), close(), health()

    Subclasses MAY override:
        - group: logical grouping (social, darkweb, feeds, etc.)
        - description: human-readable description
        - _pre_collect(), _post_normalize(): hook points

    The base class provides:
        - OPSEC-aware HTTP client via self.http
        - Structured logging via self.log
        - Timing, error handling, status tracking
        - Async context manager support
    """

    # ── Class-level metadata (override in subclasses) ──────────────────────
    connector_id: str = ""
    source_type: SourceType = SourceType.UNKNOWN
    group: str = "general"
    description: str = ""
    version: str = "1.0.0"
    is_enabled: bool = True

    def __init__(
        self,
        profile: OpsecProfile | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            profile: OPSEC security profile. Defaults to OpsecProfile.default().
            config: Connector-specific configuration (credentials, endpoints, etc.)
        """
        if not self.connector_id:
            raise TypeError(
                f"{self.__class__.__name__} must define 'connector_id' class attribute"
            )

        self._profile = profile or OpsecProfile.default()
        self._config: dict[str, Any] = config or {}
        self._status = ConnectorStatus.IDLE
        self._start_time: float | None = None
        self._last_run: datetime | None = None
        self._last_error: str | None = None
        self._total_findings: int = 0
        self._http: OpsecHttpClient | None = None

        self.log = logger.bind(connector=self.connector_id)

    # ── Abstract interface (must implement) ────────────────────────────────

    @abstractmethod
    async def connect(self) -> None:
        """
        Establish connection to the data source.
        Authenticate, verify access, initialize session.
        Raise ConnectorError on failure.
        """

    @abstractmethod
    async def collect(self, ctx: CollectionContext) -> None:
        """
        Fetch raw data from the source.
        Populate ctx.raw_items with source-specific raw data.
        """

    @abstractmethod
    async def parse(self, ctx: CollectionContext) -> None:
        """
        Transform raw_items into structured parsed_items (list of dicts).
        No domain objects yet — this is the data extraction step.
        """

    @abstractmethod
    async def normalize(self, ctx: CollectionContext) -> None:
        """
        Convert parsed_items into domain Finding objects.
        Populate ctx.findings. Apply source-specific enrichment here.
        """

    @abstractmethod
    async def close(self) -> None:
        """Cleanup connections and release all resources."""

    @abstractmethod
    async def health(self) -> ConnectorHealth:
        """
        Return current health status.
        Should be fast (no blocking I/O if possible).
        """

    # ── Template Method: run() ─────────────────────────────────────────────

    async def run(
        self,
        run_id: str,
        dry_run: bool = False,
        limit: int | None = None,
    ) -> list[Finding]:
        """
        Execute the full collection lifecycle.
        This is the primary entry point called by the pipeline.

        Template Method Pattern: skeleton here, details in subclasses.
        """
        ctx = CollectionContext(
            connector_id=self.connector_id,
            run_id=run_id,
            dry_run=dry_run,
        )
        if limit:
            ctx.metadata["limit"] = limit

        self._start_time = time.monotonic()
        self._status = ConnectorStatus.CONNECTING
        self.log.info("connector.run_start", run_id=run_id, dry_run=dry_run)

        try:
            async with OpsecHttpClient(self._profile) as http:
                self._http = http
                await self.connect()

                self._status = ConnectorStatus.COLLECTING
                await self._pre_collect(ctx)
                await self.collect(ctx)
                self.log.info("connector.collected", items=len(ctx.raw_items))

                self._status = ConnectorStatus.PARSING
                await self.parse(ctx)
                self.log.info("connector.parsed", items=len(ctx.parsed_items))

                self._status = ConnectorStatus.NORMALIZING
                await self.normalize(ctx)

                if limit and len(ctx.findings) > limit:
                    ctx.findings = ctx.findings[:limit]

                await self._post_normalize(ctx)
                self._status = ConnectorStatus.COMPLETED

        except Exception as exc:
            self._status = ConnectorStatus.ERROR
            self._last_error = str(exc)
            ctx.errors.append(str(exc))
            self.log.error("connector.run_failed", error=str(exc), exc_info=True)
        finally:
            try:
                await self.close()
            except Exception as exc:
                self.log.warning("connector.close_failed", error=str(exc))
            self._http = None

        elapsed = time.monotonic() - (self._start_time or 0)
        self._last_run = datetime.now(tz=timezone.utc)
        self._total_findings += len(ctx.findings)

        self.log.info(
            "connector.run_complete",
            findings=len(ctx.findings),
            errors=len(ctx.errors),
            elapsed_s=round(elapsed, 2),
        )
        return ctx.findings

    # ── Hook points for subclasses ─────────────────────────────────────────

    async def _pre_collect(self, ctx: CollectionContext) -> None:
        """Called before collect(). Override for pre-collection setup."""

    async def _post_normalize(self, ctx: CollectionContext) -> None:
        """Called after normalize(). Override for post-processing (e.g., enrichment)."""

    # ── HTTP convenience property ──────────────────────────────────────────

    @property
    def http(self) -> OpsecHttpClient:
        """OPSEC-configured HTTP client (only available during run())."""
        if self._http is None:
            raise RuntimeError("HTTP client is only available during connector.run()")
        return self._http

    # ── Async context manager support ─────────────────────────────────────

    async def __aenter__(self) -> "BaseConnector":
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def status(self) -> ConnectorStatus:
        return self._status

    @property
    def is_running(self) -> bool:
        return self._status in {
            ConnectorStatus.CONNECTING,
            ConnectorStatus.COLLECTING,
            ConnectorStatus.PARSING,
            ConnectorStatus.NORMALIZING,
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.connector_id!r}, status={self._status})"
