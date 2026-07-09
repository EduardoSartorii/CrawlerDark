"""Unit tests for the exfiltration analyzer."""

from __future__ import annotations

from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.models.findings import (
    DOMAnalysis,
    ExfiltrationChannel,
    FormInfo,
    JavaScriptAnalysis,
)


def test_classifies_channels() -> None:
    dom = DOMAnalysis(
        forms=[FormInfo(action="https://evil.com/next.php", method="post")]
    )
    js = JavaScriptAnalysis(
        fetch_calls=["https://api.telegram.org/bot1:AA/sendMessage"],
        axios_calls=["https://evil.com/api/v1/collect"],
        jquery_ajax_calls=["mailto:drop@evil.com"],
    )
    result = ExfiltrationAnalyzer().analyze(dom, js)
    channels = {d.destination: d.channel for d in result.destinations}
    assert channels["https://evil.com/next.php"] == ExfiltrationChannel.HTTP
    assert channels["https://api.telegram.org/bot1:AA/sendMessage"] == ExfiltrationChannel.MESSAGING
    assert channels["https://evil.com/api/v1/collect"] == ExfiltrationChannel.API
    assert channels["mailto:drop@evil.com"] == ExfiltrationChannel.EMAIL


def test_confidence_boost_for_collector_and_messaging() -> None:
    dom = DOMAnalysis(forms=[FormInfo(action="https://evil.com/gate.php", method="post")])
    result = ExfiltrationAnalyzer().analyze(dom, None)
    dest = result.destinations[0]
    # collector-named php gets a +20 boost over the HTTP base of 55.
    assert dest.confidence >= 70
    assert result.confidence == dest.confidence


def test_skips_noise_targets() -> None:
    dom = DOMAnalysis(forms=[FormInfo(action="#", method="get")])
    js = JavaScriptAnalysis(fetch_calls=["javascript:void(0)"])
    result = ExfiltrationAnalyzer().analyze(dom, js)
    assert result.destinations == []
    assert result.confidence == 0


def test_handles_none_inputs() -> None:
    result = ExfiltrationAnalyzer().analyze(None, None)
    assert result.destinations == []
