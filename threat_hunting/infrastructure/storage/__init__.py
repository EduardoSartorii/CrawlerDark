"""Storage backends implementing the Repository + Unit of Work ports.

Swapping the backend never changes a business rule. Provided out of the box:

* :class:`InMemoryUnitOfWork` -- fast, for tests/demos.
* :class:`JsonUnitOfWork` -- durable JSON file (no external dependency).
* :class:`SqliteUnitOfWork` -- durable SQLite (stdlib ``sqlite3``).

Postgres/OpenSearch/Elasticsearch/Splunk/Parquet/S3 adapters implement the same
ports and drop in identically.
"""

from threat_hunting.infrastructure.storage.memory import (
    InMemoryFindingRepository,
    InMemoryUnitOfWork,
)
from threat_hunting.infrastructure.storage.json_store import JsonUnitOfWork
from threat_hunting.infrastructure.storage.sqlite_store import SqliteUnitOfWork
from threat_hunting.infrastructure.storage.factory import StorageFactory

__all__ = [
    "InMemoryFindingRepository",
    "InMemoryUnitOfWork",
    "JsonUnitOfWork",
    "SqliteUnitOfWork",
    "StorageFactory",
]
