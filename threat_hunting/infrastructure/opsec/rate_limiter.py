"""Async token-bucket rate limiter.

Responsibility
--------------
Enforce a per-profile maximum request rate so collection stays within
operational-security and politeness limits. Implemented as a token bucket so
short bursts are allowed while the long-run average is capped.
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """A simple async token-bucket rate limiter.

    Parameters
    ----------
    rate_per_second:
        Sustained requests-per-second. Values ``<= 0`` disable limiting.
    capacity:
        Maximum burst size (defaults to one second's worth of tokens).
    """

    def __init__(self, rate_per_second: float, capacity: float | None = None) -> None:
        self._rate = max(0.0, rate_per_second)
        self._capacity = capacity if capacity is not None else max(1.0, self._rate)
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available (no-op when disabled)."""
        if self._rate <= 0:
            return
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._updated
                self._updated = now
                self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                await asyncio.sleep(deficit / self._rate)
