"""StorageFactory — encapsula a construção do backend de storage."""

from __future__ import annotations

from typing import Callable

from ..config.schemas import StorageConfig
from .sqlalchemy.engine import EngineFactory
from .sqlalchemy.models import Base
from .sqlalchemy.unit_of_work import SqlAlchemyUnitOfWork


class StorageFactory:
    """Retorna uma factory de UoW conforme o backend configurado."""

    def __init__(self, config: StorageConfig) -> None:
        self._config = config
        self._engine_factory: EngineFactory | None = None
        if config.backend == "sqlalchemy":
            self._engine_factory = EngineFactory(config.sqlalchemy)

    def uow_factory(self) -> Callable[[], SqlAlchemyUnitOfWork]:
        if self._engine_factory is None:
            raise ValueError(f"Unsupported storage backend: {self._config.backend}")
        session_factory = self._engine_factory.session_factory
        return lambda: SqlAlchemyUnitOfWork(session_factory)

    async def create_schema(self) -> None:
        """Cria o schema. Em produção usar Alembic; útil para testes/CLI init."""
        if self._engine_factory is None:
            return
        async with self._engine_factory.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        if self._engine_factory is not None:
            await self._engine_factory.dispose()
