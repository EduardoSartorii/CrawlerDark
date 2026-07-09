"""Unit tests for the pipeline orchestrator (stage ordering & isolation)."""

from __future__ import annotations

import pytest

from threat_hunting.core.application.pipeline.orchestrator import PipelineOrchestrator
from threat_hunting.core.application.ports.pipeline import PipelineContext
from threat_hunting.core.domain.exceptions import PipelineError


class _Stage:
    def __init__(self, name, fail=False):
        self.name = name
        self._fail = fail

    def process(self, context: PipelineContext) -> PipelineContext:
        if self._fail:
            raise ValueError("stage boom")
        context.bump(f"ran.{self.name}")
        return context


def test_orchestrator_runs_stages_in_order():
    orch = PipelineOrchestrator([_Stage("a"), _Stage("b")])
    assert orch.stage_names == ["a", "b"]
    ctx = orch.run(PipelineContext(connector_name="c"))
    assert ctx.stats["ran.a"] == 1
    assert ctx.stats["ran.b"] == 1


def test_orchestrator_isolates_failures_by_default():
    orch = PipelineOrchestrator([_Stage("a", fail=True), _Stage("b")])
    ctx = orch.run(PipelineContext(connector_name="c"))
    assert ctx.stats.get("ran.b") == 1  # b still ran
    assert ctx.stats["stage.failures"] == 1


def test_orchestrator_fail_fast_raises():
    orch = PipelineOrchestrator([_Stage("a", fail=True)], fail_fast=True)
    with pytest.raises(PipelineError):
        orch.run(PipelineContext(connector_name="c"))


def test_context_bump_helper():
    ctx = PipelineContext(connector_name="c")
    ctx.bump("x", 2)
    ctx.bump("x")
    assert ctx.stats["x"] == 3
