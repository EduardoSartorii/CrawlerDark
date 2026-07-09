"""Targeted tests for less-trodden branches (scoring context, run_many, MISP)."""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.dto import PipelineResult, RawRecord
from threat_hunting.core.application.use_cases.run_hunt import RunHuntUseCase
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import ConnectorStatus, IndicatorType
from threat_hunting.infrastructure.config.settings import ConnectorSettings, ScoringWeights
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.exporters.misp_exporter import MispExporter
from threat_hunting.infrastructure.scoring.engine import WeightedScoringEngine


def test_scoring_includes_context_signals() -> None:
    finding = Finding(
        title="t", source="s", connector="c",
        metadata={"source_reputation": 3.0, "recurrence": True, "seen_before": True,
                  "detection": {"rules": [], "keywords": [], "vips": [], "actors": [],
                                "brands": [], "blacklisted": False}},
    )
    WeightedScoringEngine(ScoringWeights()).score(finding)
    contributions = finding.metadata["scoring"]["contributions"]
    assert "source_reputation" in contributions
    assert "recurrence" in contributions
    assert "history" in contributions


def test_misp_event_mapping_includes_btc_and_tags() -> None:
    finding = Finding(title="Leak", source="s", connector="c", tags=["carding"])
    finding.add_indicator(Indicator(type=IndicatorType.BTC_WALLET, value="1A1zP1"))
    finding.add_indicator(Indicator(type=IndicatorType.SHA256, value="a" * 64))
    event = MispExporter._to_misp_event(finding)
    types = {a["type"] for a in event["Attribute"]}
    assert "btc" in types and "sha256" in types
    assert {"name": "carding"} in event["Tag"]


class _MiniConnector(BaseConnector):
    name = "mini"
    source = "mini"

    async def connect(self) -> None:
        return None

    async def collect(self) -> Sequence[RawRecord]:
        return []

    async def health(self) -> ConnectorStatus:
        return ConnectorStatus.HEALTHY


async def test_run_many_and_run_all_aggregate() -> None:
    class _Pipeline:
        async def run(self, connector) -> PipelineResult:
            return PipelineResult(connector=connector.name, collected=1, persisted=1)

    registry: dict[str, BaseConnector] = {"a": _MiniConnector(), "b": _MiniConnector()}
    use_case = RunHuntUseCase(
        pipeline=_Pipeline(),  # type: ignore[arg-type]
        resolve_connector=lambda name: registry[name],
        list_connectors=lambda: list(registry),
    )
    many = await use_case.run_many(["a", "b"])
    assert many.collected == 2 and many.persisted == 2
    allr = await use_case.run_all()
    assert allr.collected == 2
