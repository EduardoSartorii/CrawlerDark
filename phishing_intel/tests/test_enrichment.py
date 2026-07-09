"""Unit tests for the enrichment layer (taxonomy, campaign builder, MISP)."""

from __future__ import annotations

from phishing_intel.config.settings import MISPSettings
from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.enrichment.misp_client import MISPEnricher
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.campaign import AttributionScore
from phishing_intel.models.findings import ConfidenceLevel


# --- Taxonomy mapper --------------------------------------------------------
def test_taxonomy_tags(sample_result, high_attribution) -> None:
    tags = TaxonomyMapper().map_tags(sample_result, high_attribution)
    assert "fraude:marca=itau" in tags
    assert "fraude:objetivo=credential_harvesting" in tags
    assert "fraude:exfiltracao=http" in tags
    assert "fraude:infraestrutura=as64500" in tags
    assert "fraude:criticidade=high" in tags
    assert "fraude:campanha=camp-itau-cccccccccccc" in tags
    # No duplicate tags.
    assert len(tags) == len(set(tags))


def test_taxonomy_without_attribution(sample_result) -> None:
    tags = TaxonomyMapper().map_tags(sample_result)
    assert any(t.startswith("fraude:marca=") for t in tags)
    assert not any(t.startswith("fraude:criticidade=") for t in tags)


# --- Campaign builder -------------------------------------------------------
def test_campaign_builder_uses_attribution_id(sample_result, high_attribution) -> None:
    campaign = CampaignBuilder().build(sample_result, high_attribution)
    assert campaign.campaign_id == "CAMP-itau-cccccccccccc"
    assert campaign.score == 85
    assert campaign.confidence == ConfidenceLevel.HIGH
    assert campaign.members == [sample_result.url]


def test_campaign_builder_derives_id_when_missing(sample_result) -> None:
    attribution = AttributionScore()  # no matched campaign id
    campaign = CampaignBuilder().build(sample_result, attribution)
    # Derived deterministically from brand + fingerprint prefix.
    assert campaign.campaign_id.startswith("CAMP-itau-")


# --- MISP enricher ----------------------------------------------------------
def test_build_event_graph(sample_result, high_attribution) -> None:
    enricher = MISPEnricher(MISPSettings())
    event = enricher.build_event(sample_result, high_attribution, ["fraude:marca=itau"])
    types = {a.type for a in event.attributes}
    assert {"url", "domain", "ip-dst"} <= types
    names = {o.name for o in event.objects}
    assert {"file", "x509", "http-request", "phishing-campaign"} <= names
    assert any(t.name == "fraude:marca=itau" for t in event.tags)
    # The custom object carries the attribution + fingerprint metadata.
    campaign_obj = next(o for o in event.objects if o.name == "phishing-campaign")
    relations = {a.object_relation for a in campaign_obj.attributes}
    assert {"campaign_id", "kit_fingerprint", "target_brand", "asn"} <= relations


def test_push_disabled_returns_none(sample_result) -> None:
    enricher = MISPEnricher(MISPSettings(enabled=False))
    assert enricher.push(sample_result) == (None, None)


def test_push_uses_injected_client(sample_result, high_attribution, mocker) -> None:
    settings = MISPSettings(enabled=True)
    fake_client = mocker.Mock()
    created = mocker.Mock()
    created.uuid = "evt-uuid-123"
    created.id = 42
    fake_client.add_event.return_value = created

    enricher = MISPEnricher(settings, client=fake_client)
    uuid, event_id = enricher.push(sample_result, high_attribution, ["fraude:marca=itau"])
    assert uuid == "evt-uuid-123"
    assert event_id == "42"
    fake_client.add_event.assert_called_once()


def test_push_handles_dict_response(sample_result, mocker) -> None:
    settings = MISPSettings(enabled=True)
    fake_client = mocker.Mock()
    fake_client.add_event.return_value = {"Event": {"uuid": "dict-uuid", "id": "7"}}
    enricher = MISPEnricher(settings, client=fake_client)
    uuid, event_id = enricher.push(sample_result)
    assert uuid == "dict-uuid"
    assert event_id == "7"
