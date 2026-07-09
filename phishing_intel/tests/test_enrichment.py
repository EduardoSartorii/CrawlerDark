"""Testes de enriquecimento (taxonomia, campaign builder, MISP client)."""

from __future__ import annotations

from phishing_intel.enrichment import CampaignBuilder, MispClient, TaxonomyMapper
from phishing_intel.models.campaign import Campaign, ConfidenceLevel
from phishing_intel.models.findings import (
    AnalysisResult,
    BrandDetection,
    ExfiltrationDestination,
    ExfiltrationKind,
    PhishingType,
)
from phishing_intel.models.infrastructure import CertificateInfo, InfrastructureInfo


def _sample_analysis() -> AnalysisResult:
    """Análise de exemplo com marca, objetivos e exfiltração."""
    return AnalysisResult(
        url="https://phish.tld/login",
        domain="phish.tld",
        html_hash="h" * 64,
        phishing_types=[PhishingType.OTP_HARVESTING, PhishingType.CREDENTIAL_HARVESTING],
        exfiltration=[
            ExfiltrationDestination(
                target="https://coleta.tld/gate.php",
                kind=ExfiltrationKind.API,
                confidence=90,
            ),
            ExfiltrationDestination(
                target="drop@evil.tld", kind=ExfiltrationKind.EMAIL, confidence=60
            ),
        ],
        brand=BrandDetection(brand="itau", sector="bank", confidence=80),
    )


def _sample_campaign() -> Campaign:
    """Campanha de exemplo com alta confiança."""
    return Campaign(
        campaign_id="camp-abc",
        score=85,
        confidence=ConfidenceLevel.HIGH,
        target_brand="itau",
        phishing_type="otp",
        hosting_provider="EvilHost",
        asn="AS100",
        kit_fingerprint="kfp",
        ssl_fingerprint="sfp",
        ssl_serial="123",
    )


def test_taxonomy_mapper_builds_all_axes():
    """O mapeador deve gerar tags para todos os eixos fraude:*."""
    tags = TaxonomyMapper().build_tags(_sample_analysis(), _sample_campaign())
    joined = " ".join(tags)
    assert 'fraude:marca="itau"' in tags
    assert 'fraude:objetivo="otp"' in tags
    assert 'fraude:objetivo="credential_harvesting"' in tags
    assert 'fraude:campanha="camp-abc"' in tags
    assert 'fraude:infraestrutura="AS100"' in tags
    assert 'fraude:criticidade="alta"' in tags
    assert "fraude:exfiltracao" in joined


def test_campaign_builder_creates_payload():
    """O builder deve montar atributos, objetos x509 e phishing-campaign."""
    payload = CampaignBuilder().build(
        _sample_analysis(),
        _sample_campaign(),
        InfrastructureInfo(ip="1.2.3.4", asn="AS100"),
        CertificateInfo(sha256_fingerprint="sfp", serial_number="123", issuer="X"),
    )
    attr_types = {a["type"] for a in payload.attributes}
    assert {"url", "domain", "ip-dst", "sha256"}.issubset(attr_types)
    # Exfiltração por e-mail vira email-dst.
    assert any(a["type"] == "email-dst" for a in payload.attributes)
    obj_names = {o["name"] for o in payload.objects}
    assert "x509" in obj_names
    assert "phishing-campaign" in obj_names
    # O objeto de campanha carrega o score e o fingerprint.
    campaign_obj = next(o for o in payload.objects if o["name"] == "phishing-campaign")
    assert campaign_obj["attributes"]["campaign_score"] == 85


def test_campaign_builder_skips_empty_certificate():
    """Sem certificado, o objeto x509 não deve ser adicionado."""
    payload = CampaignBuilder().build(_sample_analysis(), _sample_campaign())
    assert all(o["name"] != "x509" for o in payload.objects)


def test_misp_client_noop_when_unavailable():
    """Sem conexão, o cliente opera em no-op e retorna ids vazios."""
    client = MispClient()
    assert client.available is False
    payload = CampaignBuilder().build(_sample_analysis(), _sample_campaign())
    assert client.push_event(payload) == ("", "")


def test_misp_client_push_with_fake_connection(mocker):
    """Com conexão injetada, o cliente deve criar o evento e retornar ids."""
    fake_result = mocker.Mock()
    fake_result.id = 42
    fake_result.uuid = "uuid-42"
    fake_conn = mocker.Mock()
    fake_conn.add_event.return_value = fake_result

    client = MispClient(connection=fake_conn)
    assert client.available is True

    payload = CampaignBuilder().build(
        _sample_analysis(),
        _sample_campaign(),
        InfrastructureInfo(ip="1.2.3.4"),
        CertificateInfo(sha256_fingerprint="sfp", serial_number="123"),
    )
    event_id, event_uuid = client.push_event(payload)
    assert event_id == "42"
    assert event_uuid == "uuid-42"
    # O evento foi de fato submetido ao MISP.
    assert fake_conn.add_event.called
