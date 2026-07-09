"""OPSEC transport abstractions for connector-safe collection."""

from threat_hunting.infrastructure.opsec.transport import HttpTransportFactory, SecretsProvider

__all__ = ["HttpTransportFactory", "SecretsProvider"]
