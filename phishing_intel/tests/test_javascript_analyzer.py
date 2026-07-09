"""Unit tests for the JavaScript analyzer."""

from __future__ import annotations

from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer


def test_extracts_network_calls() -> None:
    js = """
    fetch("https://a.com/collect");
    var x = new XMLHttpRequest(); x.open("POST", "https://b.com/xhr");
    axios.post("https://c.com/api/data");
    axios({url: "https://c2.com/cfg", method:"POST"});
    $.ajax({url: "https://d.com/save.php", method:"POST"});
    $.post("https://e.com/short");
    """
    result = JavaScriptAnalyzer().analyze([js])
    assert "https://a.com/collect" in result.fetch_calls
    assert "https://b.com/xhr" in result.xhr_calls
    assert "https://c.com/api/data" in result.axios_calls
    assert "https://c2.com/cfg" in result.axios_calls
    assert "https://d.com/save.php" in result.jquery_ajax_calls
    assert "https://e.com/short" in result.jquery_ajax_calls


def test_extracts_tokens_keys_and_suspicious() -> None:
    js = """
    var token = "abcdef1234567890";
    var k = "AKIAIOSFODNN7EXAMPLE";
    eval(atob("eA=="));
    navigator.sendBeacon("/b");
    document.cookie;
    """
    result = JavaScriptAnalyzer().analyze([js])
    assert "abcdef1234567890" in result.exposed_tokens
    assert "AKIAIOSFODNN7EXAMPLE" in result.exposed_keys
    assert any("eval" in s for s in result.suspicious_strings)
    assert any("sendBeacon" in s for s in result.suspicious_strings)


def test_dynamic_xhr_marker_when_no_url() -> None:
    result = JavaScriptAnalyzer().analyze(["var r = new XMLHttpRequest();"])
    assert any("dynamic" in c for c in result.xhr_calls)


def test_hardcoded_urls_and_empty_input() -> None:
    result = JavaScriptAnalyzer().analyze(["const u='https://hard.com/p';"])
    assert "https://hard.com/p" in result.hardcoded_urls
    empty = JavaScriptAnalyzer().analyze([])
    assert empty.fetch_calls == []
