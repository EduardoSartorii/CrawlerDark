"""Unit tests for the brand detector."""

from __future__ import annotations

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer


def _detect(html: str, url: str = "https://x.example"):
    dom = DOMAnalyzer().analyze(html, url)
    return BrandDetector().detect(dom, url)


def test_detects_brand_from_text_and_url(phishing_html: str) -> None:
    detection = _detect(phishing_html, "https://itau-secure.example/login")
    assert detection.target_brand == "itau"
    assert detection.category == "financial_institution"
    # URL match should boost confidence above a plain text-only match.
    assert detection.confidence >= 80


def test_loyalty_program_detected() -> None:
    html = "<html><head><title>Livelo Pontos</title></head><body></body></html>"
    detection = _detect(html, "https://livelo-resgate.example")
    assert detection.target_brand == "livelo"
    assert detection.category == "loyalty_program"


def test_no_brand(benign_html: str) -> None:
    detection = _detect(benign_html, "https://cats.example")
    assert detection.target_brand is None
    assert detection.confidence == 0


def test_candidates_recorded_when_multiple() -> None:
    html = "<html><head><title>Nubank e PicPay</title></head><body></body></html>"
    detection = _detect(html, "https://x.example")
    assert "nubank" in detection.candidates
    assert "picpay" in detection.candidates
