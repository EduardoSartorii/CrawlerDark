"""HTTPClientPort — abstração de rede (OPSEC-aware)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class HTTPResponsePort(Protocol):
    status_code: int
    text: str
    content: bytes

    def json(self) -> Any: ...


@runtime_checkable
class HTTPClientPort(Protocol):
    """Interface stripped-down para consumo por conectores.

    Implementada em ``infrastructure/opsec/opsec_http_client.py`` com proxy,
    rate limit, retries e user-agent rotativo.
    """

    async def get(self, url: str, **kwargs: Any) -> HTTPResponsePort: ...
    async def post(self, url: str, **kwargs: Any) -> HTTPResponsePort: ...
    async def close(self) -> None: ...
