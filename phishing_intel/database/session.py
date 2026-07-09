"""Gerenciamento de engine e sessões SQLAlchemy.

Arquitetura
-----------
Encapsula a criação do ``engine`` e da fábrica de sessões, além de um
context manager transacional que garante commit/rollback consistentes.

Responsabilidade do componente
------------------------------
Ser a única porta de entrada para conexões de banco, isolando o restante da
plataforma dos detalhes do SQLAlchemy.

Fluxo de execução
-----------------
``Database(cfg)`` -> cria engine + sessionmaker -> ``create_all`` cria o
esquema -> ``session_scope()`` fornece sessões transacionais.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from phishing_intel.config.settings import DatabaseConfig
from phishing_intel.database.models import Base
from phishing_intel.logging_config import get_logger

logger = get_logger(__name__)


class Database:
    """Gerencia o ciclo de vida de conexões com o banco de dados."""

    def __init__(self, config: DatabaseConfig | None = None) -> None:
        """Inicializa o engine e a fábrica de sessões.

        Args:
            config: Configuração do banco. Se ``None``, usa os padrões
                (SQLite local), útil para testes e execução standalone.
        """
        self.config = config or DatabaseConfig()

        # ``check_same_thread`` só é necessário/relevante para SQLite.
        connect_args = {}
        if self.config.url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        self.engine = create_engine(
            self.config.url,
            echo=self.config.echo,
            future=True,
            connect_args=connect_args,
        )
        self._session_factory = sessionmaker(
            bind=self.engine, expire_on_commit=False, class_=Session
        )

    def create_all(self) -> None:
        """Cria todas as tabelas do esquema, se ainda não existirem.

        Em produção, prefira migrações com Alembic; este método é útil para
        bootstrapping, testes e ambientes de laboratório.
        """
        Base.metadata.create_all(self.engine)
        logger.info("database_schema_ready", url=self.config.url)

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Fornece uma sessão transacional com commit/rollback automáticos.

        Yields:
            Uma :class:`sqlalchemy.orm.Session` ativa.

        A transação é confirmada ao sair normalmente do bloco ``with`` e
        revertida em caso de exceção, garantindo integridade dos dados.
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            logger.exception("database_transaction_failed")
            raise
        finally:
            session.close()
