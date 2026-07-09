"""OPSEC layer: network transport with operational-security controls.

Independent of connectors. Centralises proxies (HTTP/HTTPS/SOCKS5), VPN egress
(managed externally, selected per profile), User-Agents, rate limiting, retries
with exponential backoff and credential handling.
"""

from threat_hunting.infrastructure.opsec.rate_limiter import RateLimiter
from threat_hunting.infrastructure.opsec.transport import (
    HttpxTransport,
    TransportFactory,
)

__all__ = ["HttpxTransport", "RateLimiter", "TransportFactory"]
