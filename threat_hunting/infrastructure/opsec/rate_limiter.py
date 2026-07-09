"""Rate limiter assíncrono simples (token-bucket-like).

Sem dependências externas: mantemos o próprio lock/temporização.
"""

from __future__ import annotations

import asyncio
import time


class AsyncRateLimiter:
    """Limita ``rate`` requisições por segundo (com sleep entre chamadas)."""

    def __init__(self, rate_per_second: float) -> None:
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last: float = 0.0

    async def acquire(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
                self._last = time.monotonic()
            else:
                self._last = now
