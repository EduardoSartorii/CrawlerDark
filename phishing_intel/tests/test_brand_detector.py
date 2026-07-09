"""Testes do detector de marca-alvo (analyzers.brand_detector)."""

from __future__ import annotations

from analyzers.brand_detector import detect_brand
from analyzers.dom_analyzer import analyze_dom
from config.settings import KnownBrand


def test_detects_brand_by_keyword(sample_html: str, known_brands: list[KnownBrand]) -> None:
    dom = analyze_dom(sample_html)
    result = detect_brand(sample_html, dom, known_brands)
    assert result.target_brand == "itau"
    assert result.category == "financial_institution"
    assert "itau" in result.matched_keywords or "personnalite" in result.matched_keywords


def test_detects_brand_by_domain_reference(known_brands: list[KnownBrand]) -> None:
    html = '<html><body><a href="https://www.nubank.com.br/termos">Termos</a></body></html>'
    dom = analyze_dom(html)
    result = detect_brand(html, dom, known_brands)
    assert result.target_brand == "nubank"
    assert "nubank.com.br" in result.matched_domains


def test_no_brand_detected_returns_none(known_brands: list[KnownBrand]) -> None:
    html = "<html><body>Pagina generica sem marca</body></html>"
    dom = analyze_dom(html)
    result = detect_brand(html, dom, known_brands)
    assert result.target_brand is None
    assert result.confidence == 0.0


def test_empty_known_brands_returns_empty_result(sample_html: str) -> None:
    dom = analyze_dom(sample_html)
    result = detect_brand(sample_html, dom, [])
    assert result.target_brand is None


def test_domain_signal_outweighs_single_keyword_of_other_brand() -> None:
    brands = [
        KnownBrand(name="brand_a", category="fintech", keywords=["brand"], domains=["brand-a.com"]),
        KnownBrand(name="brand_b", category="fintech", keywords=[], domains=["brand-b.com"]),
    ]
    html = '<html><body>brand <a href="https://www.brand-b.com/login">Login</a></body></html>'
    dom = analyze_dom(html)
    result = detect_brand(html, dom, brands)
    assert result.target_brand == "brand_b"
