"""Fabrica de engine/sessao SQLAlchemy.

Responsabilidade do componente
-------------------------------
Centralizar a criacao do ``Engine`` e das sessoes SQLAlchemy a partir da
configuracao tipada (``config.settings``), expondo um context manager
seguro (``session_scope``) que garante commit/rollback consistente mesmo em
caso de excecao — essencial para nao deixar o historico de campanhas em
estado inconsistente durante falhas de coleta/analise.

Fluxo de execucao
------------------
1. ``get_engine`` cria (ou reutiliza) o ``Engine`` configurado.
2. ``init_db`` cria todas as tabelas definidas em ``database.models`` caso
   ainda nao existam (usado em testes e em ambientes sem Alembic aplicado).
3. ``session_scope`` fornece uma sessao transacional para os repositorios.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from config.settings import PhishingIntelSettings, get_settings
from database.models import Base

_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


def get_engine(settings: PhishingIntelSettings | None = None) -> Engine:
    """Cria (ou reutiliza) o Engine SQLAlchemy configurado.

    O engine e cacheado em nivel de modulo para evitar reabrir pools de
    conexao repetidamente durante a execucao de um mesmo processo.
    """
    global _engine
    if _engine is None:
        cfg = settings or get_settings()
        connect_args = {"check_same_thread": False} if cfg.database.url.startswith("sqlite") else {}
        _engine = create_engine(cfg.database.url, echo=cfg.database.echo, connect_args=connect_args)
    return _engine


def get_session_factory(settings: PhishingIntelSettings | None = None) -> sessionmaker[Session]:
    """Retorna a fabrica de sessoes associada ao engine configurado."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(settings), expire_on_commit=False)
    return _SessionFactory


def init_db(settings: PhishingIntelSettings | None = None) -> None:
    """Cria todas as tabelas do esquema caso ainda nao existam.

    Em producao, a evolucao de esquema deve ser feita via Alembic
    (``alembic upgrade head``); esta funcao existe para bootstrap rapido em
    testes e ambientes de avaliacao local (ex.: SQLite em memoria).
    """
    Base.metadata.create_all(bind=get_engine(settings))


def reset_engine_cache() -> None:
    """Reseta o cache de engine/sessao (uso exclusivo de testes)."""
    global _engine, _SessionFactory
    _engine = None
    _SessionFactory = None


@contextmanager
def session_scope(settings: PhishingIntelSettings | None = None) -> Generator[Session, None, None]:
    """Context manager transacional: commit ao sucesso, rollback ao erro."""
    session = get_session_factory(settings)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
