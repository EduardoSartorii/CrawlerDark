"""Ambiente de execucao do Alembic para o esquema phishing_intel.

Responsabilidade do componente
-------------------------------
Conectar o Alembic ao ``Engine`` configurado via ``config.settings`` e ao
metadata declarativo de ``database.models``, permitindo tanto migracoes
online (contra um banco real) quanto geracao de SQL offline.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from config.settings import get_settings
from database.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

try:
    config.set_main_option("sqlalchemy.url", get_settings().database.url)
except Exception:
    # Mantem a URL definida em alembic.ini quando a configuracao da
    # aplicacao (ex.: config.yaml com credenciais MISP obrigatorias) nao
    # estiver disponivel no ambiente atual (ex.: geracao offline de SQL).
    pass

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Executa migracoes em modo offline (gera SQL sem conexao ativa)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Executa migracoes em modo online (conexao ativa com o banco)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
