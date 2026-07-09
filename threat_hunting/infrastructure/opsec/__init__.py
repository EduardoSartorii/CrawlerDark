"""OPSEC layer: operational-security network transport.

Sits between connectors and the network and implements the core
:class:`~threat_hunting.core.application.ports.transport.Transport` port. It
centralises proxy (HTTP/HTTPS/SOCKS5/Tor), User-Agent rotation, rate limiting,
retries/backoff and secret handling into per-connector *profiles* so connectors
never manage transport concerns themselves.
"""

from threat_hunting.infrastructure.opsec.profile import OpsecProfile, RateLimit
from threat_hunting.infrastructure.opsec.manager import OpsecManager
from threat_hunting.infrastructure.opsec.transport import HttpxTransport, RateLimiter

__all__ = [
    "OpsecProfile",
    "RateLimit",
    "OpsecManager",
    "HttpxTransport",
    "RateLimiter",
]
