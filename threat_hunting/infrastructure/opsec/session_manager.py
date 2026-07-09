"""
HttpSessionManager
==================

Manages a pool of reusable httpx.AsyncClient sessions, keyed by OPSEC profile.
This avoids creating new HTTP connections for every request.

Sessions are created lazily on first use and cached for the lifetime of
the application. The manager is registered as a singleton in the DI container.
"""

from __future__ import annotations

import httpx

from threat_hunting.infrastructure.opsec.layer import OpsecLayer


class HttpSessionManager:
    """Thread-safe session pool for HTTP connections."""

    def __init__(self, opsec_layer: OpsecLayer) -> None:
        self._opsec = opsec_layer
        self._sessions: dict[str, httpx.AsyncClient] = {}

    async def get(self, profile_name: str = "standard") -> httpx.AsyncClient:
        """Return or create an AsyncClient for the given OPSEC profile."""
        if profile_name not in self._sessions or self._sessions[profile_name].is_closed:
            self._sessions[profile_name] = self._opsec.build_session(profile_name)
        return self._sessions[profile_name]

    async def close_all(self) -> None:
        """Close all managed sessions (called at application shutdown)."""
        for session in self._sessions.values():
            if not session.is_closed:
                await session.aclose()
        self._sessions.clear()
