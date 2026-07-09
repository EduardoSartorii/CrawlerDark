"""Alembic migrations package — initialize with: alembic init when using SQL backend."""

from threat_hunting.infrastructure.persistence.sqlalchemy.backend import Base, FindingModel

__all__ = ["Base", "FindingModel"]
