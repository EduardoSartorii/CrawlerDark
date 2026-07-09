"""CLI command tests for Typer entrypoints."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from threat_hunting.cli.main import app


runner = CliRunner()


def test_cli_run_reddit(test_config_path: object) -> None:
    """Validate single connector run command."""
    result = runner.invoke(app, ["run", "reddit"])
    assert result.exit_code == 0
    assert "reddit:" in result.stdout


def test_cli_run_social_bundle(test_config_path: object) -> None:
    """Validate social bundle command executes grouped connectors."""
    result = runner.invoke(app, ["run", "social"])
    assert result.exit_code == 0
    assert "reddit:" in result.stdout
    assert "github:" in result.stdout
    assert "telegram:" in result.stdout


def test_cli_connector_enable_disable(test_config_path: Path) -> None:
    """Validate connector enable/disable mutates YAML config."""
    disabled = runner.invoke(app, ["connector", "disable", "reddit"])
    enabled = runner.invoke(app, ["connector", "enable", "reddit"])
    assert disabled.exit_code == 0
    assert enabled.exit_code == 0

    final_config = test_config_path.read_text(encoding="utf-8")
    assert "reddit: true" in final_config


def test_cli_export_json(test_config_path: object) -> None:
    """Validate export command after findings generation."""
    run_result = runner.invoke(app, ["run", "github"])
    export_result = runner.invoke(app, ["export", "json"])
    assert run_result.exit_code == 0
    assert export_result.exit_code == 0
    assert "exported" in export_result.stdout


def test_cli_run_all_scheduler_and_score(test_config_path: object) -> None:
    """Validate all/scheduler/score command paths."""
    run_all = runner.invoke(app, ["run", "all"])
    scheduler = runner.invoke(app, ["scheduler", "run"])
    score = runner.invoke(app, ["score", "test"])
    assert run_all.exit_code == 0
    assert scheduler.exit_code == 0
    assert score.exit_code == 0
