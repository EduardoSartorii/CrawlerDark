"""Database engine / session management.

Responsibility
--------------
Own the SQLAlchemy ``Engine`` and ``sessionmaker`` lifecycle and provide a
convenient transactional context manager. This is the single place that knows
how to talk to the physical database.

Execution flow
--------------
``init_db(url)`` -> build engine + session factory + create tables ->
``session_scope()`` yields a session inside a try/commit/rollback block.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from phishing_intel.database.models import Base


class Database:
    """Encapsulates the engine and session factory for a single datastore."""

    def __init__(self, url: str, echo: bool = False) -> None:
        """Create the engine and initialise the schema.

        Parameters
        ----------
        url:
            SQLAlchemy database URL (e.g. ``sqlite:///phishing_intel.db``).
        echo:
            When True, SQLAlchemy logs every emitted SQL statement.
        """

        # ``check_same_thread`` is only relevant to SQLite; harmless elsewhere
        # because we branch on the dialect.
        connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
        self.engine: Engine = create_engine(url, echo=echo, future=True, connect_args=connect_args)
        self._session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.create_all()

    def create_all(self) -> None:
        """Create every table defined on the declarative ``Base``."""

        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        """Drop every table (primarily useful for tests)."""

        Base.metadata.drop_all(self.engine)

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Provide a transactional scope around a series of operations.

        Commits on success, rolls back on any exception and always closes the
        session, guaranteeing no leaked connections.
        """

        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def new_session(self) -> Session:
        """Return a raw session (caller is responsible for lifecycle)."""

        return self._session_factory()


# Module-level singleton wiring so simple scripts can share one datastore.
_DATABASE: Optional[Database] = None


def init_db(url: str, echo: bool = False) -> Database:
    """Initialise (or replace) the module-level :class:`Database` singleton."""

    global _DATABASE
    _DATABASE = Database(url=url, echo=echo)
    return _DATABASE


def get_db() -> Database:
    """Return the initialised singleton, raising if ``init_db`` was not called."""

    if _DATABASE is None:
        raise RuntimeError("Database not initialised; call init_db() first.")
    return _DATABASE
