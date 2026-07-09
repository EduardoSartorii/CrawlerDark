"""Unit tests for scheduler."""

import asyncio

import pytest

from threat_hunting.infrastructure.scheduler.jobs import HuntScheduler


@pytest.mark.asyncio
async def test_scheduler_lifecycle():
    sched = HuntScheduler()
    assert not sched.is_running

    async def dummy_handler(name):
        pass

    sched.add_connector_job("reddit", "0 */6 * * *", dummy_handler)
    assert "reddit" in sched._jobs
    sched.start()
    assert sched._scheduler.running
    sched.stop()
