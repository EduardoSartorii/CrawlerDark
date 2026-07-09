"""Testes da entidade Finding."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.exceptions import InvalidFindingError
from threat_hunting.core.domain.value_objects import (
    Category,
    IndicatorType,
    Score,
    Severity,
    SourceRef,
)


def _src():
    return SourceRef(source="t", connector="ut")


def test_requires_title():
    with pytest.raises(InvalidFindingError):
        Finding(title=" ", source=_src(), connector="ut")


def test_add_indicator_deduplicates_by_type_and_value():
    f = Finding(title="x", source=_src(), connector="ut")
    f.add_indicator(Indicator(type=IndicatorType.IP, value="1.2.3.4"))
    f.add_indicator(Indicator(type=IndicatorType.IP, value="1.2.3.4"))
    assert len(f.indicators) == 1


def test_set_score_records_event():
    f = Finding(title="x", source=_src(), connector="ut")
    f.set_score(Score(87.5), "test")
    assert float(f.score) == 87.5
    assert any(e.kind == "score.updated" for e in f.timeline)


def test_add_tags_touch_updates_updated_at():
    f = Finding(title="x", source=_src(), connector="ut")
    before = f.updated_at
    import time; time.sleep(0.001)
    f.add_tags("phishing", "urgent")
    assert f.updated_at > before
    assert {"phishing", "urgent"}.issubset(f.tags)


def test_mark_exported_updates_exported_to():
    f = Finding(title="x", source=_src(), connector="ut")
    f.mark_exported("misp")
    f.mark_exported("misp")
    assert f.exported_to == {"misp"}


def test_category_and_severity_defaults():
    f = Finding(title="x", source=_src(), connector="ut")
    assert f.category is Category.OTHER
    assert f.severity is Severity.INFO
