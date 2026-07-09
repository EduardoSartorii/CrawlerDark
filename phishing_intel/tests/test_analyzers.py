"""Testes dos analisadores estáticos (DOM, JS, form, exfiltração, kit, brand)."""

from __future__ import annotations

from phishing_intel.analyzers import (
    BrandDetector,
    DomAnalyzer,
    ExfiltrationAnalyzer,
    FormClassifier,
    JavaScriptAnalyzer,
    KitFingerprinter,
)
from phishing_intel.models.findings import ExfiltrationKind, PhishingType


def test_dom_analyzer_extracts_structure(sample_html):
    """O DOM analyzer deve extrair formulários, scripts, assets e metatags."""
    dom = DomAnalyzer().analyze(sample_html, base_url="https://livelo-fake.tld/x")
    assert dom.title == "Livelo - Resgate seus pontos"
    assert len(dom.forms) == 1
    form = dom.forms[0]
    assert form.action == "https://coleta.evil.tld/gate.php"
    assert form.method == "post"
    assert "cpf" in form.input_names
    assert "sid" in form.hidden_fields
    assert "CPF" in form.labels
    assert any("app.min.js" in s for s in dom.scripts_external)
    assert "description" in dom.meta_tags
    assert "kit build v3" in dom.comments
    # URL externa (outro domínio) deve ser detectada.
    assert any("cdn.terceiro.tld" in u for u in dom.external_urls)
    assert dom.normalized_skeleton.startswith("html>head>title")


def test_dom_analyzer_empty_html():
    """HTML vazio deve produzir estrutura vazia sem erro."""
    dom = DomAnalyzer().analyze("")
    assert dom.forms == []
    assert dom.normalized_skeleton == ""


def test_javascript_analyzer_extracts_calls_and_secrets(sample_js):
    """O JS analyzer deve capturar fetch/xhr/axios/jquery, chaves e tokens."""
    js = JavaScriptAnalyzer().analyze(sample_js)
    assert any("result.php" in u for u in js.fetch_urls)
    assert any("save.php" in u for u in js.xhr_urls)
    assert any("/api/log" in u for u in js.axios_urls)
    assert any("telegram" in u for u in js.jquery_ajax_urls)
    assert any(k.startswith("AIza") for k in js.exposed_keys)
    assert js.exposed_tokens  # JWT/bearer detectados
    assert js.suspicious_strings  # termos suspeitos presentes


def test_javascript_analyzer_empty():
    """JS vazio (lista ou string) deve produzir achados vazios."""
    assert JavaScriptAnalyzer().analyze([]).fetch_urls == []
    assert JavaScriptAnalyzer().analyze("").hardcoded_urls == []


def test_form_classifier_detects_account_takeover(sample_html):
    """Senha + OTP + documentos devem gerar múltiplas classificações."""
    dom = DomAnalyzer().analyze(sample_html)
    types = FormClassifier().classify(dom)
    assert PhishingType.CREDENTIAL_HARVESTING in types
    assert PhishingType.OTP_HARVESTING in types
    assert PhishingType.IDENTITY_THEFT in types
    # Credencial + OTP juntos => account takeover.
    assert PhishingType.ACCOUNT_TAKEOVER in types


def test_form_classifier_card_harvesting():
    """Campos de cartão devem gerar CARD_HARVESTING."""
    html = (
        "<form action='/x'><input name='card_number'>"
        "<input name='cvv'><input name='validade'></form>"
    )
    dom = DomAnalyzer().analyze(html)
    types = FormClassifier().classify(dom)
    assert PhishingType.CARD_HARVESTING in types


def test_form_classifier_generic_fallback():
    """Formulário sem sinais específicos deve cair em coleta genérica."""
    dom = DomAnalyzer().analyze("<form action='/x'><input name='foo'></form>")
    types = FormClassifier().classify(dom)
    assert types == [PhishingType.GENERIC_DATA_COLLECTION]


def test_form_classifier_no_forms():
    """Sem formulários, nenhuma classificação é retornada."""
    dom = DomAnalyzer().analyze("<div>hello</div>")
    assert FormClassifier().classify(dom) == []


def test_exfiltration_analyzer_classifies_channels(sample_html, sample_js):
    """A exfiltração deve identificar destinos HTTP e de mensageria."""
    dom = DomAnalyzer().analyze(sample_html)
    js = JavaScriptAnalyzer().analyze([sample_js])
    dests = ExfiltrationAnalyzer().analyze(dom, js)
    targets = {d.target for d in dests}
    # O action do formulário é o destino de maior confiança.
    assert "https://coleta.evil.tld/gate.php" in targets
    # Telegram deve ser classificado como mensageria.
    messaging = [d for d in dests if d.kind == ExfiltrationKind.MESSAGING]
    assert messaging
    # Ordenado por confiança (decrescente).
    confidences = [d.confidence for d in dests]
    assert confidences == sorted(confidences, reverse=True)


def test_exfiltration_ignores_empty_actions():
    """Actions vazias ou 'javascript:void(0)' não geram destinos."""
    dom = DomAnalyzer().analyze("<form action='#'><input name='a'></form>")
    js = JavaScriptAnalyzer().analyze("")
    assert ExfiltrationAnalyzer().analyze(dom, js) == []


def test_kit_fingerprint_is_deterministic(sample_html):
    """O fingerprint deve ser estável para o mesmo DOM e mudar com o DOM."""
    dom = DomAnalyzer().analyze(sample_html)
    fp1 = KitFingerprinter().fingerprint(dom)
    fp2 = KitFingerprinter().fingerprint(dom)
    assert fp1.campaign_fingerprint == fp2.campaign_fingerprint
    assert len(fp1.dom_hash) == 64
    dom_other = DomAnalyzer().analyze("<html><body><p>x</p></body></html>")
    fp3 = KitFingerprinter().fingerprint(dom_other)
    assert fp3.campaign_fingerprint != fp1.campaign_fingerprint


def test_brand_detector_identifies_livelo(sample_html):
    """A marca Livelo deve ser detectada pelo título/metatags/assets."""
    dom = DomAnalyzer().analyze(sample_html)
    brand = BrandDetector().detect(dom)
    assert brand is not None
    assert brand.brand == "livelo"
    assert brand.sector == "loyalty"
    assert brand.confidence >= 40


def test_brand_detector_returns_none_for_unknown():
    """Página sem marca conhecida deve retornar None."""
    dom = DomAnalyzer().analyze("<html><title>Random</title></html>")
    assert BrandDetector().detect(dom) is None
