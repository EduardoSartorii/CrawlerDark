"""Integration tests for full platform bootstrap."""

import pytest


@pytest.fixture
def test_db_url(tmp_path):
    return f"sqlite+aiosqlite:///{tmp_path}/test.db"


@pytest.mark.asyncio
async def test_bootstrap(test_db_url):
    from threat_hunting.config.container import bootstrap
    ctx = await bootstrap(database_url=test_db_url)
    assert "registry" in ctx
    assert "pipeline" in ctx
    assert len(ctx["registry"].list_names()) > 0


@pytest.mark.asyncio
async def test_run_connector_integration(test_db_url):
    from threat_hunting.config.container import bootstrap
    from threat_hunting.core.application.commands import RunConnectorCommand

    ctx = await bootstrap(database_url=test_db_url)
    result = await ctx["run_handler"].handle(
        RunConnectorCommand(connector_name="reddit", keywords=["malware"])
    )
    assert result["connector"] == "reddit"
    assert "findings_count" in result


@pytest.mark.asyncio
async def test_score_test_handler(test_db_url):
    from threat_hunting.config.container import bootstrap
    from threat_hunting.core.application.commands import ScoreTestCommand

    ctx = await bootstrap(database_url=test_db_url)
    result = await ctx["score_test_handler"].handle(ScoreTestCommand())
    assert "score" in result
