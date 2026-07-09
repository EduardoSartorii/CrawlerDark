"""Tests for plugin discovery and Typer CLI commands."""

from __future__ import annotations

from typer.testing import CliRunner

from threat_hunting.cli.app import app
from threat_hunting.plugins.manager import ConnectorPluginManager


def test_connector_plugin_discovery() -> None:
    manager = ConnectorPluginManager()
    registry = manager.discover()
    assert "reddit" in registry
    assert "github" in registry
    assert "telegram" in registry


def test_cli_run_reddit() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["run", "reddit"])
    assert result.exit_code == 0
    assert "findings=" in result.stdout


def test_cli_score_test() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["score", "test"])
    assert result.exit_code == 0
    assert "score=" in result.stdout


def test_cli_connector_scheduler_export_and_health() -> None:
    runner = CliRunner()

    enabled = runner.invoke(app, ["connector", "enable", "reddit"])
    assert enabled.exit_code == 0
    assert "enabled" in enabled.stdout

    disabled = runner.invoke(app, ["connector", "disable", "reddit"])
    assert disabled.exit_code == 0
    assert "disabled" in disabled.stdout

    scheduler = runner.invoke(app, ["scheduler", "run"])
    assert scheduler.exit_code == 0
    assert "scheduler_executed" in scheduler.stdout

    exported = runner.invoke(app, ["export", "elastic"])
    assert exported.exit_code == 0
    assert "opensearch" in exported.stdout

    health = runner.invoke(app, ["health"])
    assert health.exit_code == 0
    assert "status" in health.stdout


def test_cli_invalid_score_action_fails() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["score", "invalid"])
    assert result.exit_code != 0
