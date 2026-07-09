"""Unit tests for the HTML parser and default normalizer."""

from __future__ import annotations

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType
from threat_hunting.infrastructure.normalizers.default_normalizer import (
    DefaultNormalizer,
)
from threat_hunting.infrastructure.parsers.html_parser import HtmlTextParser


def test_html_parser_strips_markup_and_scripts() -> None:
    record = RawRecord(
        source="s",
        connector="c",
        content="<html><script>bad()</script><p>Hello   world</p></html>",
    )
    parsed = HtmlTextParser().parse(record)
    assert "bad()" not in parsed.content
    assert "Hello world" in parsed.content
    assert parsed.metadata["content_length"] > 0


def test_html_parser_leaves_plain_text() -> None:
    record = RawRecord(source="s", connector="c", content="just text here")
    assert HtmlTextParser().parse(record).content == "just text here"


def test_normalizer_populates_normalized_data() -> None:
    finding = Finding(title="t", source="s", connector="c")
    finding.add_indicator(Indicator(type=IndicatorType.IPV4, value="1.2.3.4"))
    record = RawRecord(source="s", connector="c", content="body text", url="http://x")
    DefaultNormalizer().normalize(finding, record)
    assert finding.normalized_data["text"] == "body text"
    assert finding.normalized_data["indicator_total"] == 1
    assert finding.normalized_data["indicator_summary"] == {"ipv4": 1}
