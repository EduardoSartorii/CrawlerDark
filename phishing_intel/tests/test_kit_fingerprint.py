"""Testes do gerador de fingerprint de kit (analyzers.kit_fingerprint)."""

from __future__ import annotations

from analyzers.dom_analyzer import analyze_dom
from analyzers.javascript_analyzer import analyze_javascript
from analyzers.kit_fingerprint import generate_kit_fingerprint


def test_fingerprint_is_deterministic(sample_html: str, sample_js: str) -> None:
    dom = analyze_dom(sample_html)
    js = analyze_javascript(sample_js)

    fp1 = generate_kit_fingerprint(dom, js)
    fp2 = generate_kit_fingerprint(dom, js)

    assert fp1.campaign_fingerprint == fp2.campaign_fingerprint
    assert fp1.dom_sha256 == fp2.dom_sha256
    assert fp1.assets_sha256 == fp2.assets_sha256
    assert fp1.scripts_sha256 == fp2.scripts_sha256


def test_fingerprint_matches_when_kit_reused_with_different_brand_text() -> None:
    """Mesmo layout/assets/scripts, apenas o texto/marca mudou -> mesmo fingerprint."""
    html_itau = """
    <html><head><title>Itau Seguro</title></head>
    <body>
        <img src="/assets/logo.png">
        <form id="f1" action="/collect" method="POST">
            <input type="text" name="user">
            <input type="password" name="pass">
        </form>
        <script src="/assets/app.js"></script>
    </body></html>
    """
    html_nubank = """
    <html><head><title>Nubank Seguro</title></head>
    <body>
        <img src="/assets/logo.png">
        <form id="f1" action="/collect" method="POST">
            <input type="text" name="user">
            <input type="password" name="pass">
        </form>
        <script src="/assets/app.js"></script>
    </body></html>
    """
    js = analyze_javascript("")

    fp_itau = generate_kit_fingerprint(analyze_dom(html_itau), js)
    fp_nubank = generate_kit_fingerprint(analyze_dom(html_nubank), js)

    assert fp_itau.campaign_fingerprint == fp_nubank.campaign_fingerprint


def test_fingerprint_differs_when_structure_changes() -> None:
    html_a = '<html><body><form id="f1" method="POST"><input type="text" name="user"></form></body></html>'
    html_b = '<html><body><form id="f1" method="POST"><input type="text" name="user"><input type="password" name="pass"></form></body></html>'
    js = analyze_javascript("")

    fp_a = generate_kit_fingerprint(analyze_dom(html_a), js)
    fp_b = generate_kit_fingerprint(analyze_dom(html_b), js)

    assert fp_a.campaign_fingerprint != fp_b.campaign_fingerprint


def test_fingerprint_handles_empty_page() -> None:
    dom = analyze_dom("<html></html>")
    js = analyze_javascript("")
    fingerprint = generate_kit_fingerprint(dom, js)
    assert len(fingerprint.campaign_fingerprint) == 64
