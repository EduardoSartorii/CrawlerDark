"""Core layer: domain model and application (use cases + ports).

The core is framework-agnostic and infrastructure-agnostic. It must never
import from :mod:`threat_hunting.infrastructure` or :mod:`threat_hunting.cli`.
This constraint is enforced by ``tests/unit/test_architecture.py``.
"""
