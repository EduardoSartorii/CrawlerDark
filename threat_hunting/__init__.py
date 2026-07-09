"""Threat Hunting Collection platform package.

The package is intentionally layered: domain and application modules are
framework-agnostic, while infrastructure modules adapt databases, HTTP clients,
observability and external CTI products.
"""

__all__ = ["__version__"]

__version__ = "0.1.0"
