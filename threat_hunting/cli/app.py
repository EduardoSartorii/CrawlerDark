"""Ponto de entrada da CLI (comando ``hunt``)."""

from __future__ import annotations

import typer

from .commands import connector as connector_cmd
from .commands import export as export_cmd
from .commands import health as health_cmd
from .commands import init as init_cmd
from .commands import run as run_cmd
from .commands import scheduler as scheduler_cmd
from .commands import score as score_cmd

app = typer.Typer(
    name="hunt",
    help="Threat Hunting Platform — CLI operacional.",
    no_args_is_help=True,
    add_completion=False,
)

app.add_typer(run_cmd.app, name="run", help="Executa conectores individualmente ou em lote.")
app.add_typer(connector_cmd.app, name="connector", help="Gerencia conectores (list/enable/disable).")
app.add_typer(export_cmd.app, name="export", help="Exportações sob demanda para MISP, STIX, JSON etc.")
app.add_typer(scheduler_cmd.app, name="scheduler", help="Scheduler de jobs periódicos.")
app.add_typer(score_cmd.app, name="score", help="Utilitários do motor de score.")
app.command("health")(health_cmd.health)
app.command("init")(init_cmd.init_db)


if __name__ == "__main__":  # pragma: no cover
    app()
