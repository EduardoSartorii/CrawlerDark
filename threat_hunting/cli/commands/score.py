"""`hunt score test` — utilitários do motor de score."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from ...core.application.pipeline import PipelineContext
from ...core.domain.builders import FindingBuilder
from ...core.domain.value_objects import Category, Severity, SourceRef
from .._helpers import bootstrap, run_async

app = typer.Typer(help="Utilitários do motor de score.")
console = Console()


@app.command("test")
def test(
    text: str = typer.Option(
        "Combolist: user:password AWS AKIAIOSFODNN7EXAMPLE, 4111 1111 1111 1111",
        help="Texto de teste para pontuação.",
    ),
    category: str = typer.Option("CREDENTIAL"),
    severity: str = typer.Option("HIGH"),
    connector: str = typer.Option("cli.score.test"),
    config_dir: str = typer.Option("config", help="Diretório de configuração."),
) -> None:
    """Constrói um finding sintético e mostra o score final."""
    run_async(lambda: _test(text, category, severity, connector, config_dir))


async def _test(text: str, category: str, severity: str, connector: str, config_dir: str) -> None:
    root = await bootstrap(config_dir)
    src = SourceRef(source="cli.score", connector=connector)
    finding = (
        FindingBuilder()
        .title("cli score test")
        .description(text)
        .source(src)
        .category(Category.coerce(category))
        .severity(Severity.from_string(severity))
        .build()
    )
    ctx = PipelineContext(connector=connector, payload=None, finding=finding)

    # Aplica apenas estágios de análise (sem persist/export).
    analysis_stages = {"extract", "canonicalize", "detect", "score"}
    for stage in root.orchestrator._stages:  # type: ignore[attr-defined]
        if stage.name in analysis_stages:
            ctx = await stage.run(ctx)

    result = ctx.finding
    assert result is not None
    table = Table(title="Score result", header_style="bold magenta")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("title", result.title)
    table.add_row("category", result.category.value)
    table.add_row("severity", result.severity.name)
    table.add_row("score", f"{float(result.score):.2f}")
    table.add_row("tags", ", ".join(sorted(result.tags)) or "-")
    table.add_row("indicators", str(len(result.indicators)))
    for i in result.indicators[:20]:
        table.add_row(f"  {i.type.value}", i.value)
    console.print(table)
    await root.shutdown()
