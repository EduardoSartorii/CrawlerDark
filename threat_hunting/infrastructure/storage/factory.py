"""StorageFactory.

Responsibility
--------------
Build the configured :class:`UnitOfWork` from a backend name + options, so
callers select a backend by *data* (config) rather than importing a concrete
class. Adding a new backend (postgres, opensearch, ...) is a new branch here and
a new adapter module — no caller changes.
"""

from __future__ import annotations

from typing import Any

from threat_hunting.core.application.ports.repository import UnitOfWork
from threat_hunting.core.domain.exceptions import ConfigurationError
from threat_hunting.infrastructure.storage.json_store import JsonUnitOfWork
from threat_hunting.infrastructure.storage.memory import InMemoryUnitOfWork
from threat_hunting.infrastructure.storage.sqlite_store import SqliteUnitOfWork


class StorageFactory:
    """Creates unit-of-work instances from a backend name."""

    @staticmethod
    def build(backend: str, **options: Any) -> UnitOfWork:
        """Return the unit of work for ``backend`` (memory | json | sqlite)."""
        backend = backend.lower()
        if backend == "memory":
            return InMemoryUnitOfWork()
        if backend == "json":
            path = options.get("path", "data/findings.json")
            return JsonUnitOfWork(path)
        if backend == "sqlite":
            path = options.get("path", "data/findings.db")
            return SqliteUnitOfWork(path)
        raise ConfigurationError(
            f"Unknown storage backend '{backend}'. Supported: memory, json, sqlite."
        )
