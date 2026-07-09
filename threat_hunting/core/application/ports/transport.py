"""Transport port (OPSEC network abstraction).

Responsibility
--------------
Abstract *all* network egress behind a minimal contract so connectors never
touch sockets/HTTP libraries directly. The OPSEC layer implements this port and
transparently applies proxies (HTTP/HTTPS/SOCKS5/Tor), rotating User-Agents,
rate limiting, retries and backoff per connector profile.

Keeping this in the core (as a port) is what lets the OPSEC policy be enforced
uniformly and swapped without any connector change.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class TransportResponse(BaseModel):
    """A normalised HTTP-style response returned by a :class:`Transport`."""

    status_code: int
    text: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    url: str = ""

    @property
    def ok(self) -> bool:
        """Whether the response is a 2xx success."""
        return 200 <= self.status_code < 300


@runtime_checkable
class Transport(Protocol):
    """Contract for performing network requests under an OPSEC profile."""

    def get(self, url: str, **kwargs: Any) -> TransportResponse:
        """Perform a GET request applying the active OPSEC profile."""
        ...

    def request(self, method: str, url: str, **kwargs: Any) -> TransportResponse:
        """Perform an arbitrary HTTP request applying the active OPSEC profile."""
        ...
