"""
OPSEC (Operational Security) Layer.

Provides transparent operational security for all network-based connectors.
This layer sits between connectors and the network, abstracting:
    - Proxy routing (HTTP, HTTPS, SOCKS5, Tor)
    - User-Agent rotation and browser fingerprint spoofing
    - Rate limiting and adaptive backoff
    - Per-connector security profiles
    - Credential management (never in source code)

Architectural Principle:
    Connectors should not know about OPSEC details.
    They request an HTTP client; OPSEC provides one pre-configured for their profile.
"""

from .http_client import OpsecHttpClient
from .profiles import OpsecProfile, ProxyConfig

__all__ = ["OpsecHttpClient", "OpsecProfile", "ProxyConfig"]
