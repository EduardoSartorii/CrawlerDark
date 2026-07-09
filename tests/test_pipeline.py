"""Pipeline integration tests."""

from __future__ import annotations

from pathlib import Path

from threat_hunting.connectors.registry import ConnectorRegistry
from threat_hunting.core.application.pipeline import CollectionPipeline


def test_pipeline_runs_complete_flow_and_exports_high_score(
    tmp_path: Path, registry: ConnectorRegistry, pipeline: CollectionPipeline
) -> None:
    """Pipeline should collect, detect, score, persist, enrich, and export."""

    findings = pipeline.run(registry.create("github"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.connector == "github"
    assert finding.score >= 60
    assert finding.severity.value in {"high", "critical"}
    assert any(indicator.value == "admin@acme.test" for indicator in finding.indicators)
    assert finding.metadata["enrichment"]["tenant"] == "test"
    assert (tmp_path / "export.json").exists()


def test_pipeline_eliminates_duplicate_findings(registry: ConnectorRegistry, pipeline: CollectionPipeline) -> None:
    """Pipeline should skip repeated observations."""

    first = pipeline.run(registry.create("github"))
    second = pipeline.run(registry.create("github"))

    assert len(first) == 1
    assert second == []
