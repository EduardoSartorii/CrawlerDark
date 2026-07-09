"""Unit tests for the DOM analyzer."""

from __future__ import annotations

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer


def test_extracts_forms_fields_and_hidden(phishing_html: str) -> None:
    dom = DOMAnalyzer().analyze(phishing_html, "https://itau-secure.example/login")
    assert len(dom.forms) == 1
    form = dom.forms[0]
    assert form.action == "https://collector.evil/next.php"
    assert form.method == "post"
    assert form.id == "loginForm"
    assert "auth-box" in form.css_classes
    names = {f.name for f in form.fields}
    assert {"cpf", "senha", "cvv", "otp_token", "csrf"} <= names
    # The hidden csrf field is captured in hidden_fields.
    assert any(f.name == "csrf" and f.hidden for f in dom.hidden_fields)


def test_resolves_labels_placeholders(phishing_html: str) -> None:
    dom = DOMAnalyzer().analyze(phishing_html, "https://itau-secure.example/login")
    cpf = next(f for f in dom.forms[0].fields if f.name == "cpf")
    assert cpf.label == "CPF"
    assert cpf.placeholder == "Digite seu CPF"


def test_scripts_links_assets_meta_comments(phishing_html: str) -> None:
    dom = DOMAnalyzer().analyze(phishing_html, "https://itau-secure.example/login")
    assert dom.scripts_inline  # inline submit handler present
    assert "/js/app.min.js" in dom.scripts_external
    assert "https://external-cdn.example/jquery.js" in dom.scripts_external
    # External resources leaving the base domain are flagged.
    assert any("external-cdn.example" in u for u in dom.external_urls)
    assert dom.meta_tags.get("application-name") == "Itau"
    assert any("kit build" in c for c in dom.comments)
    assert "app.min.js" in dom.filenames


def test_structural_hash_is_deterministic_and_content_insensitive() -> None:
    analyzer = DOMAnalyzer()
    a = "<html><body><form><input name='x'></form></body></html>"
    # Same structure, different attribute values / text.
    b = "<html><body><form><input name='y' value='z'></form></body></html>"
    ha = analyzer.analyze(a).structural_hash
    hb = analyzer.analyze(b).structural_hash
    assert ha == hb
    # A genuinely different structure yields a different hash.
    c = "<html><body><div><span></span></div></body></html>"
    assert analyzer.analyze(c).structural_hash != ha


def test_empty_html_is_safe() -> None:
    dom = DOMAnalyzer().analyze("", None)
    assert dom.forms == []
    assert dom.structural_hash is not None
