"""
BaseConnector — Connector SDK Base Class
=========================================

All connectors must extend BaseConnector.
BaseConnector implements the IConnector port and provides:
    - OPSEC-aware HTTP session management
    - Structured logging with connector context
    - Retry logic (via tenacity)
    - Rate limiting (delegated to OpsecLayer)
    - Common lifecycle management (connect/close)
    - Abstract hooks for collect(), parse(), normalize(), health()

How to add a new connector:
    1. Create a new Python file in the appropriate subdirectory:
       threat_hunting/infrastructure/connectors/<category>/<name>.py
    2. Define a class that inherits from BaseConnector.
    3. Set class attributes: connector_id, connector_name, source_type.
    4. Implement the four abstract methods: collect(), parse(), normalize(), health().
    5. That's it — the ConnectorRegistry discovers it automatically.

The connector MUST NOT:
    - Import from any module outside infrastructure.
    - Modify the Core domain logic.
    - Manage its own HTTP session lifecycle.
    - Hardcode credentials or proxies.

The connector MUST:
    - Use self._session for all HTTP requests (OPSEC-managed).
    - Call self._throttle() before each HTTP request.
    - Return Finding objects from normalize() using FindingBuilder.
"""

from __future__ import annotations

import time
from abc import abstractmethod
from typing import TYPE_CHECKING, Any, AsyncIterator

import httpx
import structlog
from tenacity import (
    AsyncRetrying,
    RetryError,
    stop_after_attempt,
    wait_exponential,
)

from threat_hunting.core.domain.exceptions.domain_exceptions import (
    CollectionError,
    ConnectorError,
)
from threat_hunting.core.domain.ports.connectors import IConnector, ConnectorHealthStatus

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.infrastructure.opsec.layer import OpsecLayer


class BaseConnector(IConnector):
    """
    Abstract base class for all connectors.

    Provides OPSEC-aware HTTP access, logging, retry, and rate limiting.
    Subclasses implement collect(), parse(), normalize(), and health().
    """

    # Subclasses MUST override these.
    connector_id: str = ""
    connector_name: str = ""
    source_type: str = ""

    def __init__(
        self,
        opsec_layer: "OpsecLayer",
        config: dict[str, Any] | None = None,
        opsec_profile: str = "standard",
    ) -> None:
        if not self.connector_id:
            raise ConnectorError(
                f"Connector class {self.__class__.__name__} must define connector_id"
            )
        self._opsec = opsec_layer
        self._config = config or {}
        self._opsec_profile = opsec_profile
        self._session: httpx.AsyncClient | None = None
        self._logger = structlog.get_logger(__name__).bind(
            connector=self.connector_id,
            source=self.source_type,
        )

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open an OPSEC-managed HTTP session."""
        self._session = self._opsec.build_session(self._opsec_profile)
        self._logger.debug("connector_connected")

    async def close(self) -> None:
        """Close the HTTP session and release resources."""
        if self._session and not self._session.is_closed:
            await self._session.aclose()
        self._logger.debug("connector_closed")

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    async def _get(self, url: str, **kwargs: Any) -> httpx.Response:
        """
        Perform a rate-limited, retried GET request.

        Args:
            url: Target URL.
            **kwargs: Extra arguments forwarded to httpx.AsyncClient.get().

        Returns:
            httpx.Response

        Raises:
            CollectionError: When all retry attempts are exhausted.
        """
        await self._opsec.throttle(self._opsec_profile)
        profile = self._opsec.get_profile(self._opsec_profile)

        if self._session is None:
            await self.connect()

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(profile.max_retries),
                wait=wait_exponential(
                    multiplier=profile.backoff_factor, min=1, max=60
                ),
                reraise=True,
            ):
                with attempt:
                    assert self._session is not None
                    response = await self._session.get(url, **kwargs)
                    response.raise_for_status()
                    return response
        except RetryError as exc:
            raise CollectionError(
                f"GET {url!r} failed after retries",
                context={"connector": self.connector_id, "url": url},
            ) from exc
        except httpx.HTTPStatusError as exc:
            raise CollectionError(
                f"HTTP {exc.response.status_code} for {url!r}",
                context={"connector": self.connector_id, "url": url, "status": exc.response.status_code},
            ) from exc

        raise CollectionError(f"GET {url!r} failed unexpectedly")

    async def _post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Perform a rate-limited, retried POST request."""
        await self._opsec.throttle(self._opsec_profile)
        profile = self._opsec.get_profile(self._opsec_profile)

        if self._session is None:
            await self.connect()

        try:
            async for attempt in AsyncRetrying(
                stop=stop_after_attempt(profile.max_retries),
                wait=wait_exponential(multiplier=profile.backoff_factor, min=1, max=60),
                reraise=True,
            ):
                with attempt:
                    assert self._session is not None
                    response = await self._session.post(url, **kwargs)
                    response.raise_for_status()
                    return response
        except RetryError as exc:
            raise CollectionError(f"POST {url!r} failed after retries") from exc

        raise CollectionError(f"POST {url!r} failed unexpectedly")

    # ── Throttling ─────────────────────────────────────────────────────────────

    async def _throttle(self) -> None:
        """Manually apply rate limiting before a request."""
        await self._opsec.throttle(self._opsec_profile)

    # ── Abstract interface ─────────────────────────────────────────────────────

    @abstractmethod
    async def collect(self) -> AsyncIterator[dict]:
        """Yield raw items from the source."""

    @abstractmethod
    async def parse(self, raw_item: dict) -> dict:
        """Convert a raw item to a structured dict."""

    @abstractmethod
    async def normalize(self, parsed_item: dict) -> "Finding":
        """Convert a structured dict to a Finding."""

    @abstractmethod
    async def health(self) -> ConnectorHealthStatus:
        """Check connector health."""

    # ── Health helper ──────────────────────────────────────────────────────────

    async def _measure_latency(self, url: str) -> float:
        """Measure latency to a URL in milliseconds."""
        start = time.perf_counter()
        try:
            await self._get(url)
            return (time.perf_counter() - start) * 1000
        except Exception:
            return -1.0

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.connector_id!r})"
