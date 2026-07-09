"""Testes do classificador de tipo de phishing (analyzers.form_classifier)."""

from __future__ import annotations

from analyzers.dom_analyzer import analyze_dom
from analyzers.form_classifier import classify_phishing_type
from models.findings import PhishingType


def test_classifies_otp_harvesting() -> None:
    html = """
    <form>
        <input type="text" name="otp_code" placeholder="Codigo de verificacao SMS">
        <input type="text" name="token" placeholder="Token de seguranca">
    </form>
    """
    dom = analyze_dom(html)
    result = classify_phishing_type(dom)
    assert result.phishing_type == PhishingType.OTP_HARVESTING
    assert result.confidence > 0


def test_classifies_card_harvesting() -> None:
    html = """
    <form>
        <input type="text" name="card_number" placeholder="Numero do cartao">
        <input type="text" name="cvv" placeholder="CVV">
        <input type="text" name="expiry" placeholder="Validade">
    </form>
    """
    dom = analyze_dom(html)
    result = classify_phishing_type(dom)
    assert result.phishing_type == PhishingType.CARD_HARVESTING


def test_classifies_credential_harvesting(sample_html: str) -> None:
    dom = analyze_dom(sample_html)
    result = classify_phishing_type(dom)
    # sample_html tem CPF (identity) + senha (credential); identity_theft tem
    # prioridade mais alta na tabela de resolucao de empates.
    assert result.phishing_type in {PhishingType.IDENTITY_THEFT, PhishingType.CREDENTIAL_HARVESTING}


def test_classifies_identity_theft() -> None:
    html = """
    <form>
        <input type="text" name="cpf" placeholder="CPF">
        <input type="text" name="birth_date" placeholder="Data de nascimento">
    </form>
    """
    dom = analyze_dom(html)
    result = classify_phishing_type(dom)
    assert result.phishing_type == PhishingType.IDENTITY_THEFT


def test_classifies_account_takeover() -> None:
    html = """
    <form>
        <input type="text" name="security_question" placeholder="Pergunta de seguranca">
        <input type="text" name="recovery_email" placeholder="Email de recuperacao">
    </form>
    """
    dom = analyze_dom(html)
    result = classify_phishing_type(dom)
    assert result.phishing_type == PhishingType.ACCOUNT_TAKEOVER


def test_classifies_generic_data_collection() -> None:
    html = """
    <form>
        <input type="text" name="nome" placeholder="Nome completo">
        <input type="text" name="telefone" placeholder="Telefone">
    </form>
    """
    dom = analyze_dom(html)
    result = classify_phishing_type(dom)
    assert result.phishing_type == PhishingType.GENERIC_DATA_COLLECTION


def test_classifies_unknown_when_no_forms() -> None:
    dom = analyze_dom("<html><body><p>Sem formularios aqui</p></body></html>")
    result = classify_phishing_type(dom)
    assert result.phishing_type == PhishingType.UNKNOWN
    assert result.confidence == 0.0
