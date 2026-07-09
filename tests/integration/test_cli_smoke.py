"""Smoke test da CLI Typer usando o CliRunner."""

from __future__ import annotations

from typer.testing import CliRunner

from threat_hunting.cli.app import app


def test_cli_help_shows_all_commands():
    runner = CliRunner()
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ["run", "connector", "export", "scheduler", "score", "health", "init"]:
        assert cmd in result.stdout


def test_cli_connector_list_runs():
    runner = CliRunner()
    result = runner.invoke(app, ["connector", "list", "--config-dir", "config"])
    assert result.exit_code == 0
    assert "rss_krebs" in result.stdout or "Connectors" in result.stdout


def test_cli_score_test_runs():
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["score", "test", "--text", "AWS AKIAIOSFODNN7EXAMPLE"],
    )
    assert result.exit_code == 0
    assert "score" in result.stdout.lower()
