"""Unit tests — domain entities, value objects, builder."""

from __future__ import annotations

import pytest

from threat_hunting.core.domain.entities import Finding, HuntJob, Watchlist
from threat_hunting.core.domain.enums import (
    FindingCategory,
    HuntJobStatus,
    IndicatorType,
    Severity,
    WatchlistType,
)
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import (
    Confidence,
    ContentHash,
    Indicator,
    Keyword,
    Score,
    Tag,
)


def test_finding_builder_requires_title() -> None:
    with pytest.raises(ValueError):
        FindingBuilder().with_source("x").with_connector("y").build()


def test_finding_builder_success() -> None:
    f = (
        FindingBuilder()
        .with_title("Test")
        .with_source("reddit")
        .with_connector("reddit")
        .with_category(FindingCategory.OSINT)
        .add_tag("demo")
        .build()
    )
    assert f.title == "Test"
    assert f.tags[0].name == "demo"
    assert f.content_hash


def test_finding_add_indicator_dedup() -> None:
    f = (
        FindingBuilder()
        .with_title("T")
        .with_source("s")
        .with_connector("c")
        .build()
    )
    ind = Indicator(type=IndicatorType.IP, value="1.2.3.4")
    f.add_indicator(ind)
    f.add_indicator(ind)
    assert len(f.indicators) == 1


def test_score_bounds_and_exceeds() -> None:
    s = Score(value=80)
    assert s.exceeds(75)
    assert not s.exceeds(90)
    assert float(s.with_delta(50)) == 100.0
    assert float(s.with_delta(-200)) == 0.0


def test_keyword_match() -> None:
    kw = Keyword(value="Acme", case_sensitive=False, whole_word=True)
    assert kw.matches("The Acme Corp leak")
    assert not kw.matches("AcmeCorp")


def test_content_hash_stable() -> None:
    a = ContentHash.from_text("Hello   World")
    b = ContentHash.from_text("hello world")
    assert a.value == b.value


def test_tag_normalization() -> None:
    assert Tag(name="  Hello World ").name == "hello_world"


def test_hunt_job_lifecycle() -> None:
    job = HuntJob(connector="reddit")
    job.start()
    assert job.status == HuntJobStatus.RUNNING
    job.record_finding()
    job.record_finding(is_duplicate=True)
    job.complete()
    assert job.findings_count == 2
    assert job.duplicates_count == 1
    assert job.status == HuntJobStatus.COMPLETED


def test_watchlist_contains() -> None:
    w = Watchlist(name="brands", type=WatchlistType.BRAND, entries=["Acme"])
    assert w.contains("acme")
    w.add_entry("Beta")
    assert "Beta" in w.entries


def test_finding_export_dict(sample_finding: Finding) -> None:
    d = sample_finding.to_export_dict()
    assert d["title"]
    assert d["score"] >= 0
    assert isinstance(d["indicators"], list)


def test_confidence() -> None:
    c = Confidence(value=0.8)
    assert float(c) == 0.8
