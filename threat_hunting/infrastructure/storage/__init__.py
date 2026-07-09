"""Storage layer — plugável por backend. Default: SQLAlchemy 2 async."""

from .factory import StorageFactory

__all__ = ["StorageFactory"]
