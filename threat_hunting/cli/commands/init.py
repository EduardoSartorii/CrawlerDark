"""`hunt init` — bootstrap do schema e watchlists no storage."""

from __future__ import annotations

import typer
from rich.console import Console

from .._helpers import bootstrap, run_async


def init_db(config_dir: str = typer.Option("config", help="Diretório de configuração.")) -> None:
    """Cria as tabelas e semeia watchlists iniciais."""
    run_async(lambda: _init(config_dir))


async def _init(config_dir: str) -> None:
    console = Console()
    root = await bootstrap(config_dir)
    await root.create_schema()
    console.print("[green]Schema created and watchlist seeded.[/green]")
    await root.shutdown()
