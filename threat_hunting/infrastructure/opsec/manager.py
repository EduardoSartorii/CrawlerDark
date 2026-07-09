"""OPSEC manager.

Responsibility
--------------
Own the catalogue of :class:`OpsecProfile`s and hand connectors the correct
:class:`Transport` for their profile. This is the single place that decides
*how* egress happens, decoupling that policy from every connector (Factory
Pattern for transports).
"""

from __future__ import annotations

from threat_hunting.core.application.ports.transport import Transport
from threat_hunting.infrastructure.opsec.profile import OpsecProfile
from threat_hunting.infrastructure.opsec.transport import HttpxTransport, OfflineTransport


class OpsecManager:
    """Resolves per-connector transports from named OPSEC profiles."""

    def __init__(
        self,
        profiles: dict[str, OpsecProfile] | None = None,
        *,
        connector_profiles: dict[str, str] | None = None,
        offline: bool = False,
    ) -> None:
        """Store profiles and the connector→profile mapping.

        :param offline: when ``True`` every transport is an
            :class:`OfflineTransport` (useful for restricted CI/sandboxes).
        """
        self._profiles = profiles or {"default": OpsecProfile()}
        self._profiles.setdefault("default", OpsecProfile())
        self._connector_profiles = connector_profiles or {}
        self._offline = offline

    def profile_for(self, connector_name: str) -> OpsecProfile:
        """Return the profile assigned to ``connector_name`` (or the default)."""
        profile_name = self._connector_profiles.get(connector_name, "default")
        return self._profiles.get(profile_name, self._profiles["default"])

    def transport_for(self, connector_name: str) -> Transport:
        """Build the :class:`Transport` a connector should use to reach the net."""
        profile = self.profile_for(connector_name)
        if self._offline:
            return OfflineTransport(profile)
        return HttpxTransport(profile)
