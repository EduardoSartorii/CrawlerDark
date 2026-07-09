"""
RateLimiter
===========

Token-bucket rate limiter for controlling outbound request rate per connector.
Each OpsecProfile has its own RateLimiter instance.

Implements the token-bucket algorithm:
    - Tokens are added at 'rate_rps' tokens per second.
    - Each request consumes one token.
    - When the bucket is empty, the caller sleeps until a token is available.
    - Maximum burst = bucket capacity (default = rate_rps * 2).
"""

from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token-bucket rate limiter."""

    def __init__(self, rate_rps: float, burst_multiplier: float = 2.0) -> None:
        if rate_rps <= 0:
            raise ValueError(f"rate_rps must be positive, got {rate_rps}")
        self._rate = rate_rps
        self._capacity = rate_rps * burst_multiplier
        self._tokens = self._capacity
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire one token, sleeping if the bucket is empty."""
        async with self._lock:
            self._refill()
            if self._tokens < 1:
                sleep_duration = (1 - self._tokens) / self._rate
                await asyncio.sleep(sleep_duration)
                self._refill()
            self._tokens -= 1

    def _refill(self) -> None:
        """Add tokens based on time elapsed since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    @property
    def available_tokens(self) -> float:
        """Current token count (for monitoring)."""
        return self._tokens
