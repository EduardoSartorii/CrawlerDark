"""Unit tests for the phishing-type form classifier."""

from __future__ import annotations

from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.models.findings import PhishingType


def _classify(html: str):
    dom = DOMAnalyzer().analyze(html, "https://x.example")
    return FormClassifier().classify(dom)


def test_credential_and_card_and_otp(phishing_html: str) -> None:
    result = _classify(phishing_html)
    detected = result.detected_types
    assert PhishingType.CREDENTIAL_HARVESTING in detected
    assert PhishingType.CARD_HARVESTING in detected
    assert PhishingType.OTP_HARVESTING in detected
    # Password field pushes credential harvesting to the top.
    assert result.primary_type == PhishingType.CREDENTIAL_HARVESTING
    assert result.confidence > 0


def test_identity_theft_detected() -> None:
    html = """<form><input name="cpf"><input name="data_nascimento">
    <input name="nome_da_mae"></form>"""
    result = _classify(html)
    assert PhishingType.IDENTITY_THEFT in result.detected_types


def test_account_takeover_from_recovery_cues() -> None:
    # Recovery/verification cues appear in the title + field labels, which the
    # classifier scans alongside credential fields to infer account takeover.
    html = """<html><head><title>Verifique e confirme sua conta</title></head><body>
    <form action="/x">
      <label for="email">E-mail da conta</label><input id="email" name="email">
      <input type="password" name="senha">
      <button>Desbloquear conta</button>
    </form></body></html>"""
    dom = DOMAnalyzer().analyze(html, "https://x.example")
    result = FormClassifier().classify(dom)
    assert PhishingType.ACCOUNT_TAKEOVER in result.detected_types


def test_generic_when_form_without_cues() -> None:
    html = "<form><input name='q'></form>"
    result = _classify(html)
    assert result.primary_type == PhishingType.GENERIC_DATA_COLLECTION


def test_no_forms_zero_confidence(benign_html: str) -> None:
    result = _classify(benign_html)
    assert result.confidence == 0
    assert result.detected_types == {}
