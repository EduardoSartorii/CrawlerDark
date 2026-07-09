"""Storage adapters: Repository + Unit of Work over pluggable backends.

Every backend implements the same ports, so switching between in-memory, SQLite,
PostgreSQL or a JSON data lake never changes a business rule (verified by
``tests/integration/test_storage_backends.py``).
"""

from threat_hunting.infrastructure.storage.json_repo import (
    JsonFindingRepository,
    JsonUnitOfWork,
)
from threat_hunting.infrastructure.storage.memory_repo import (
    InMemoryFindingRepository,
    InMemoryUnitOfWork,
)
from threat_hunting.infrastructure.storage.sqlalchemy_repo import (
    SqlAlchemyUnitOfWork,
    build_engine,
)

__all__ = [
    "InMemoryFindingRepository",
    "InMemoryUnitOfWork",
    "JsonFindingRepository",
    "JsonUnitOfWork",
    "SqlAlchemyUnitOfWork",
    "build_engine",
]
