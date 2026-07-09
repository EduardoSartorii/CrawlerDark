"""OPSEC transport ports.

Responsibility
--------------
Abstract *how* the platform reaches the network so that operational security
(proxies, SOCKS5/Tor, VPN egress, per-connector profiles, User-Agents, rate
limiting, retries/backoff, credential injection) is configured centrally and is
completely decoupled from connectors. A connector asks the transport factory for
a transport bound to its profile and never manages network concerns itself.

Patterns
--------
* **Factory**: ``TransportFactoryPort.for_profile`` builds a configured
  transport.
* **Adapter**: the concrete transport wraps httpx / SOCKS / Tor.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class TransportResponse:
    """A minimal, transport-agnostic HTTP response."""

    status_code: int
    text: str
    headers: dict[str, str] = field(default_factory=dict)
    url: str = ""

    @property
    def ok(self) -> bool:
        """Whether the response is a 2xx success."""
        return 200 <= self.status_code < 300


class TransportPort(abc.ABC):
    """A network transport bound to a specific OPSEC profile."""

    #: The OPSEC profile name this transport was built for.
    profile: str = "default"

    @abc.abstractmethod
    async def get(
        self, url: str, *, params: dict[str, Any] | None = None
    ) -> TransportResponse:
        """Perform a GET request honouring the profile's OPSEC settings."""

    @abc.abstractmethod
    async def post(
        self, url: str, *, data: Any | None = None, json: Any | None = None
    ) -> TransportResponse:
        """Perform a POST request honouring the profile's OPSEC settings."""

    @abc.abstractmethod
    async def aclose(self) -> None:
        """Release the underlying network resources."""


class TransportFactoryPort(abc.ABC):
    """Builds transports for named OPSEC profiles (central configuration)."""

    @abc.abstractmethod
    def for_profile(self, profile: str) -> TransportPort:
        """Return a transport configured for the given OPSEC profile."""
