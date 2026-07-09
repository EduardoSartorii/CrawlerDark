"""Integration tests: every storage backend honours the same ports.

This proves the platform's promise that switching backends changes no business
rule — the same operations round-trip a finding identically across in-memory,
SQLite and JSONL.
"""

from __future__ import annotations

import pytest

from threat_hunting.core.application.ports.repository import UnitOfWorkPort
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.infrastructure.storage.json_repo import JsonUnitOfWork
from threat_hunting.infrastructure.storage.memory_repo import InMemoryUnitOfWork
from threat_hunting.infrastructure.storage.sqlalchemy_repo import (
    SqlAlchemyUnitOfWork,
    build_engine,
)


def _make_uow(kind: str, tmp_path) -> UnitOfWorkPort:
    if kind == "memory":
        return InMemoryUnitOfWork()
    if kind == "sqlite":
        return SqlAlchemyUnitOfWork(build_engine(f"sqlite:///{tmp_path/'t.db'}"))
    return JsonUnitOfWork(tmp_path / "findings.jsonl")


def _finding() -> Finding:
    f = Finding(title="Leak", source="s", connector="c")
    f.add_indicator(Indicator(type=IndicatorType.DOMAIN, value="acme.com"))
    f.set_score(88)
    f.metadata["fingerprint"] = "fp-123"
    return f


@pytest.mark.parametrize("kind", ["memory", "sqlite", "json"])
def test_round_trip_persist_and_read(kind: str, tmp_path) -> None:
    uow = _make_uow(kind, tmp_path)
    finding = _finding()

    with uow:
        uow.findings.add(finding)

    stored = uow.findings.list()
    assert len(stored) == 1
    restored = stored[0]
    assert restored.title == "Leak"
    assert restored.score == 88.0
    assert restored.indicators[0].value == "acme.com"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_get_and_recent(kind: str, tmp_path) -> None:
    uow = _make_uow(kind, tmp_path)
    finding = _finding()
    with uow:
        uow.findings.add(finding)
    assert uow.findings.get(finding.id) is not None
    assert len(uow.findings.recent(limit=10)) == 1


def test_json_rollback_discards(tmp_path) -> None:
    uow = JsonUnitOfWork(tmp_path / "f.jsonl")
    try:
        with uow:
            uow.findings.add(_finding())
            raise RuntimeError("fail before commit")
    except RuntimeError:
        pass
    assert uow.findings.list() == []
