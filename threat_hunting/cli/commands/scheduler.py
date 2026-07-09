"""`hunt scheduler run` — inicia o scheduler com jobs de ``config/scheduler.yaml``."""

from __future__ import annotations

import asyncio

import typer
from rich.console import Console

from .._helpers import bootstrap

app = typer.Typer(help="Scheduler periódico (APScheduler).")
console = Console()


@app.command("run")
def run(config_dir: str = typer.Option("config", help="Diretório de configuração.")) -> None:
    """Roda o scheduler indefinidamente (Ctrl+C para sair)."""
    asyncio.run(_run(config_dir))


@app.command("list")
def list_(config_dir: str = typer.Option("config", help="Diretório de configuração.")) -> None:
    """Lista jobs planejados."""
    jobs = _load_jobs_from_yaml(config_dir)
    console.print(f"[bold]Planned jobs[/bold]: {len(jobs)}")
    for j in jobs:
        console.print(f" • {j['id']} → connector={j['connector']} trigger={j['trigger']}")


def _load_jobs_from_yaml(config_dir: str) -> list[dict]:
    from pathlib import Path
    import yaml

    path = Path(config_dir) / "scheduler.yaml"
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data.get("jobs", [])


async def _run(config_dir: str) -> None:
    root = await bootstrap(config_dir, ensure_schema=True)
    jobs = _load_jobs_from_yaml(config_dir)
    for job in jobs:
        job_id = job["id"]
        connector_name = job["connector"]
        trigger = job["trigger"]
        trigger_opts = {k: v for k, v in job.items() if k not in {"id", "connector", "trigger"}}

        async def _run_one(name: str = connector_name) -> None:
            connector = root.build_connector(name)
            await root.run_connector_uc.execute(connector)

        root.scheduler.add_job(job_id, _run_one, trigger=trigger, **trigger_opts)
        console.print(f"[green]+ scheduled[/green] {job_id} ({connector_name} / {trigger})")

    await root.scheduler.start()
    console.print("[bold cyan]Scheduler running — Ctrl+C to stop[/bold cyan]")
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await root.shutdown()
