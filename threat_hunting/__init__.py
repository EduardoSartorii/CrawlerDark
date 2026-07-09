"""Threat Hunting Collection Platform.

A modular, production-oriented Cyber Threat Intelligence (CTI) collection
platform built with Clean Architecture, Domain-Driven Design and Hexagonal
(Ports & Adapters) principles.

The public surface intentionally exposes only the version. Everything else is
reached through the layered packages (``core`` / ``infrastructure`` / ``cli``)
so the dependency direction stays explicit.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
