"""Unit tests for storage backends (Repository + Unit of Work)."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.core.domain.exceptions import ConfigurationError
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.infrastructure.storage.factory import StorageFactory


def _finding(title="t"):
    return (
        FindingBuilder(title, "sample_paste", "s")
        .add_indicator(Indicator(type=IndicatorType.DOMAIN, value="evil.com"))
        .build()
    )


@pytest.fixture(params=["memory", "json", "sqlite"])
def uow(request, tmp_path):
    backend = request.param
    if backend == "memory":
        return StorageFactory.build("memory")
    if backend == "json":
        return StorageFactory.build("json", path=str(tmp_path / "f.json"))
    return StorageFactory.build("sqlite", path=str(tmp_path / "f.db"))


def test_add_commit_and_count(uow):
    with uow as u:
        u.findings.add(_finding())
    with uow as u:
        assert u.findings.count() == 1


def test_get_and_find_by_indicator(uow):
    finding = _finding("lookup")
    with uow as u:
        u.findings.add(finding)
    with uow as u:
        assert u.findings.get(finding.id).title == "lookup"
        assert u.findings.find_by_indicator("domain:evil.com")
        assert u.findings.get("missing") is None


def test_rollback_on_exception(uow):
    with pytest.raises(RuntimeError):
        with uow as u:
            u.findings.add(_finding())
            raise RuntimeError("abort")
    with uow as u:
        assert u.findings.count() == 0


def test_list_limit(uow):
    with uow as u:
        for i in range(3):
            u.findings.add(_finding(f"f{i}"))
    with uow as u:
        assert len(u.findings.list(limit=2)) == 2


def test_unknown_backend_raises():
    with pytest.raises(ConfigurationError):
        StorageFactory.build("cassandra")
