"""Threat Hunting Collection Platform.

A modular, production-grade Cyber Threat Intelligence (CTI) collection platform
built on Clean Architecture, Hexagonal (Ports & Adapters), Domain Driven Design
and an event-driven collection pipeline.

Package layout (see ``docs/ARCHITECTURE.md`` for the full rationale):

* :mod:`threat_hunting.core` -- pure business core (domain + application).
* :mod:`threat_hunting.infrastructure` -- adapters implementing core ports.
* :mod:`threat_hunting.config` -- settings and the dependency-injection root.
* :mod:`threat_hunting.cli` -- the Typer command line entrypoint (``hunt``).
"""

__version__ = "0.1.0"
