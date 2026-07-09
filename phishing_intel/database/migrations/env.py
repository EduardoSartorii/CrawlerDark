"""Ambiente de execução das migrações Alembic.

Arquitetura
-----------
Integra o Alembic ao esquema declarativo da plataforma. A URL do banco é
resolvida a partir da configuração da aplicação (YAML/env), e o
``target_metadata`` aponta para :data:`phishing_intel.database.models.Base`,
permitindo autogeração de migrações.

Fluxo de execução
-----------------
Alembic chama ``run_migrations_online`` (ou ``_offline``), que cria o engine
e aplica as migrações dentro de uma transação.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from phishing_intel.config import load_config
from phishing_intel.database.models import Base

# Objeto de configuração do Alembic (lê alembic.ini).
config = context.config

# Configura o logging do Alembic a partir do arquivo .ini, se presente.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Resolve a URL do banco pela configuração da aplicação (fonte única).
app_config = load_config()
config.set_main_option("sqlalchemy.url", app_config.database.url)

# Metadados de destino para autogeração de migrações.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Executa migrações em modo offline (sem engine, apenas emite SQL)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Executa migrações em modo online (conecta ao banco real)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
