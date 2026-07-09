"""Testes do analisador de DOM (analyzers.dom_analyzer)."""

from __future__ import annotations

from analyzers.dom_analyzer import analyze_dom


def test_analyze_dom_extracts_forms_and_hidden_fields(sample_html: str) -> None:
    dom = analyze_dom(sample_html, base_url="https://phish.example/login")

    assert len(dom.forms) == 1
    form = dom.forms[0]
    assert form.action == "https://collector.evil-domain.test/api/collect"
    assert form.method == "POST"
    assert form.form_id == "login-form"

    field_names = {field.name for field in form.fields}
    assert {"cpf", "senha", "csrf_token"}.issubset(field_names)

    hidden_fields = [field for field in form.fields if field.is_hidden]
    assert len(hidden_fields) == 1
    assert hidden_fields[0].name == "csrf_token"


def test_analyze_dom_extracts_scripts_inline_and_external(sample_html: str) -> None:
    dom = analyze_dom(sample_html)
    external_scripts = [s for s in dom.scripts if not s.is_inline]
    inline_scripts = [s for s in dom.scripts if s.is_inline]

    assert len(external_scripts) == 1
    assert external_scripts[0].filename == "app.js"
    assert len(inline_scripts) == 1
    assert inline_scripts[0].inline_content_hash is not None


def test_analyze_dom_extracts_assets_links_meta_and_comments(sample_html: str) -> None:
    dom = analyze_dom(sample_html)

    assert any(asset.filename == "logo-itau.png" for asset in dom.assets)
    assert any(asset.asset_type == "stylesheet" for asset in dom.assets)
    assert "https://www.itau.com.br/institucional" in dom.links
    assert dom.meta_tags.get("description") == "Portal seguro Itau Personnalite"
    assert any("kit-version" in comment for comment in dom.comments)
    assert dom.title == "Itau - Confirme seus dados"


def test_analyze_dom_extracts_css_classes_and_html_ids(sample_html: str) -> None:
    dom = analyze_dom(sample_html)
    assert "logo" in dom.css_classes
    assert "login-form" in dom.html_ids
    assert "cpf" in dom.html_ids
    assert "senha" in dom.html_ids


def test_analyze_dom_external_urls_excludes_base_domain(sample_html: str) -> None:
    dom = analyze_dom(sample_html, base_url="https://phish.example/login")
    assert any("evil-domain.test" in url for url in dom.external_urls)
    assert any("itau.com.br" in url for url in dom.external_urls)


def test_structural_hash_is_deterministic_and_content_agnostic() -> None:
    html_a = '<html><body><form id="f1" action="/x" method="POST"><input type="text" name="user"></form></body></html>'
    html_b = '<html><body><form id="f2" action="/y" method="POST"><input type="text" name="login"></form></body></html>'

    dom_a = analyze_dom(html_a)
    dom_b = analyze_dom(html_b)

    # `id` e `name` sao atributos estruturais: como diferem entre A e B, os
    # hashes tambem devem diferir.
    assert dom_a.structural_hash != dom_b.structural_hash

    html_c = '<html><body><form id="f1" action="/z" method="POST"><input type="text" name="user"></form></body></html>'
    dom_c = analyze_dom(html_c)
    # Apenas o `action` (nao estrutural) mudou -> hash deve permanecer igual.
    assert dom_a.structural_hash == dom_c.structural_hash


def test_analyze_dom_handles_empty_html() -> None:
    dom = analyze_dom("")
    assert dom.forms == []
    assert dom.scripts == []
    assert dom.structural_hash != ""
