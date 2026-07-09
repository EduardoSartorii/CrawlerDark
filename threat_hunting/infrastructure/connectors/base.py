"""BaseConnector: the connector SDK (Template Method Pattern).

Responsibility
--------------
Provide the abstract base every connector inherits. It fixes the collection
lifecycle (``connect → collect → parse → normalize → health → close``) and
supplies safe defaults so a concrete connector usually only implements
``collect`` (and optionally ``parse``). The base also gives every connector an
OPSEC :class:`Transport`, guaranteeing egress policy is always applied and the
connector never opens sockets directly.

Business rules
--------------
* A connector declares immutable :class:`ConnectorMeta` via the class attribute
  ``meta`` — used by the registry for discovery, grouping and enable/disable.
* ``parse`` returns a canonical :class:`Finding`; ``normalize`` may refine it.
  Downstream pipeline engines (detection/scoring/...) are shared and connector
  agnostic.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta, HealthStatus
from threat_hunting.core.application.ports.transport import Transport, TransportResponse
from threat_hunting.core.domain.entities.finding import Finding, FindingBuilder
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.exceptions import CollectionError


class _NullTransport:
    """Transport used when a connector is instantiated without OPSEC wiring."""

    def get(self, url: str, **kwargs: object) -> TransportResponse:
        return TransportResponse(status_code=0, text="", url=url)

    def request(self, method: str, url: str, **kwargs: object) -> TransportResponse:
        return TransportResponse(status_code=0, text="", url=url)


class BaseConnector(abc.ABC):
    """Abstract base for every data-source connector.

    Subclasses MUST define a class-level ``meta`` (:class:`ConnectorMeta`) and
    implement :meth:`collect`. Everything else has a sensible default.
    """

    #: Every concrete connector overrides this. Left ``None`` on the abstract
    #: base and on non-leaf helper classes so the registry skips them.
    meta: ConnectorMeta | None = None

    def __init__(self, transport: Transport | None = None) -> None:
        """Store the OPSEC transport used for all network access."""
        self._transport: Transport = transport or _NullTransport()  # type: ignore[assignment]

    # -- lifecycle --------------------------------------------------------
    def connect(self) -> None:
        """Establish any session/auth. Default is a no-op (override if needed)."""
        return None

    @abc.abstractmethod
    def collect(self) -> Iterable[RawItem]:
        """Yield raw items from the source. The one method every connector needs."""
        raise NotImplementedError

    def parse(self, item: RawItem) -> Finding:
        """Turn a raw item into a canonical finding (safe default implementation).

        The default builds a finding from the raw item's title/content and
        copies its payload into ``raw_data``. Connectors override this only when
        source-specific structuring is required.
        """
        title = item.title or (item.content[:80] if item.content else f"item from {item.source}")
        builder = (
            FindingBuilder(title=title, connector=item.connector, source=item.source)
            .description(item.content)
            .category(self._require_meta().category)
            .raw_data(item.payload)
            .metadata({"url": item.url or "", "raw_item_id": item.id})
        )
        return builder.build()

    def normalize(self, finding: Finding) -> Finding:
        """Apply connector-specific normalisation (default: identity)."""
        return finding

    def health(self) -> HealthStatus:
        """Probe connector reachability (default: reports healthy)."""
        meta = self._require_meta()
        return HealthStatus(healthy=True, component=meta.name, detail="default health ok")

    def close(self) -> None:
        """Release resources. Closes the transport if it exposes ``close``."""
        close = getattr(self._transport, "close", None)
        if callable(close):
            close()

    # -- helpers ----------------------------------------------------------
    @property
    def transport(self) -> Transport:
        """The OPSEC transport this connector must use for network access."""
        return self._transport

    def _require_meta(self) -> ConnectorMeta:
        """Return ``meta`` or raise if a subclass forgot to declare it."""
        if self.meta is None:
            raise CollectionError(f"{type(self).__name__} is missing a 'meta' declaration")
        return self.meta
