"""
Repository pattern for database CRUD operations.

Encapsulates all persistence logic for campaigns, sites, certificates,
infrastructure, fingerprints, and MISP events.

Architectural Responsibility:
    Data access layer isolating SQLAlchemy queries from business logic
    in analyzers, correlators, and enrichment modules.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishing_intel.database.models import (
    CampaignModel,
    CertificateModel,
    FingerprintModel,
    InfrastructureModel,
    MISPEventModel,
    PhishingSiteModel,
)
from phishing_intel.models.campaign import Campaign, CampaignAttribution
from phishing_intel.models.findings import AnalysisResult, ConfidenceLevel


class CampaignRepository:
    """CRUD operations for campaign entities."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, campaign: Campaign) -> CampaignModel:
        """Persist a new campaign record."""
        model = CampaignModel(
            campaign_id=campaign.campaign_id,
            score=campaign.attribution.score if campaign.attribution else 0.0,
            confidence=(
                campaign.attribution.confidence.value
                if campaign.attribution
                else ConfidenceLevel.LOW.value
            ),
            target_brand=campaign.target_brand,
            phishing_type=campaign.phishing_type,
            kit_fingerprint=campaign.kit_fingerprint,
            incident_count=campaign.incident_count,
            tags=json.dumps(campaign.tags),
            metadata_json=json.dumps(campaign.metadata),
        )
        self.session.add(model)
        self.session.flush()
        return model

    def get_by_id(self, campaign_id: str) -> CampaignModel | None:
        """Retrieve campaign by campaign_id."""
        return self.session.execute(
            select(CampaignModel).where(CampaignModel.campaign_id == campaign_id)
        ).scalar_one_or_none()

    def get_by_fingerprint(self, fingerprint: str) -> CampaignModel | None:
        """Find campaign matching kit fingerprint."""
        return self.session.execute(
            select(CampaignModel).where(CampaignModel.kit_fingerprint == fingerprint)
        ).scalar_one_or_none()

    def update_score(
        self, campaign_id: str, score: float, confidence: str
    ) -> CampaignModel | None:
        """Update attribution score and confidence level."""
        campaign = self.get_by_id(campaign_id)
        if campaign:
            campaign.score = score
            campaign.confidence = confidence
            campaign.updated_at = datetime.now(timezone.utc)
            self.session.flush()
        return campaign

    def list_all(self, limit: int = 100) -> list[CampaignModel]:
        """List campaigns ordered by most recent."""
        return list(
            self.session.execute(
                select(CampaignModel).order_by(CampaignModel.updated_at.desc()).limit(limit)
            ).scalars()
        )


class PhishingSiteRepository:
    """CRUD operations for analyzed phishing sites."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, result: AnalysisResult, campaign_id: str = "") -> PhishingSiteModel:
        """Persist analysis result as phishing site record."""
        from phishing_intel.utils import extract_domain

        model = PhishingSiteModel(
            url=result.url,
            domain=extract_domain(result.url),
            html_hash=result.html_hash,
            javascript_hash=result.javascript_hash,
            campaign_id=campaign_id,
            phishing_type=result.phishing_type.value,
            target_brand=result.brand.brand if result.brand else "",
            analysis_json=result.model_dump_json(),
        )
        self.session.add(model)
        self.session.flush()
        return model

    def get_by_url(self, url: str) -> PhishingSiteModel | None:
        """Retrieve site by URL."""
        return self.session.execute(
            select(PhishingSiteModel).where(PhishingSiteModel.url == url)
        ).scalar_one_or_none()

    def get_by_html_hash(self, html_hash: str) -> list[PhishingSiteModel]:
        """Find sites with matching HTML hash."""
        return list(
            self.session.execute(
                select(PhishingSiteModel).where(PhishingSiteModel.html_hash == html_hash)
            ).scalars()
        )

    def get_by_campaign(self, campaign_id: str) -> list[PhishingSiteModel]:
        """List all sites in a campaign."""
        return list(
            self.session.execute(
                select(PhishingSiteModel).where(PhishingSiteModel.campaign_id == campaign_id)
            ).scalars()
        )


class CertificateRepository:
    """CRUD operations for SSL certificates."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, cert_data: dict[str, Any], site_url: str = "") -> CertificateModel:
        """Persist certificate record."""
        model = CertificateModel(
            serial_number=cert_data.get("serial_number", ""),
            issuer=cert_data.get("issuer", ""),
            subject=cert_data.get("subject", ""),
            sha1_fingerprint=cert_data.get("sha1_fingerprint", ""),
            sha256_fingerprint=cert_data.get("sha256_fingerprint", ""),
            san=json.dumps(cert_data.get("san", [])),
            not_before=cert_data.get("not_before"),
            not_after=cert_data.get("not_after"),
            raw_pem=cert_data.get("raw_certificate", ""),
            site_url=site_url,
        )
        self.session.add(model)
        self.session.flush()
        return model

    def get_by_fingerprint(self, sha1: str) -> list[CertificateModel]:
        """Find certificates by SHA1 fingerprint."""
        return list(
            self.session.execute(
                select(CertificateModel).where(CertificateModel.sha1_fingerprint == sha1)
            ).scalars()
        )


class InfrastructureRepository:
    """CRUD operations for hosting infrastructure."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, infra_data: dict[str, Any]) -> InfrastructureModel:
        """Persist infrastructure record."""
        model = InfrastructureModel(
            ip=infra_data.get("ip", ""),
            domain=infra_data.get("domain", ""),
            asn=infra_data.get("asn", ""),
            organization=infra_data.get("organization", ""),
            provider=infra_data.get("hosting_provider", ""),
            country=infra_data.get("country", ""),
        )
        self.session.add(model)
        self.session.flush()
        return model

    def get_by_ip(self, ip: str) -> list[InfrastructureModel]:
        """Find infrastructure records by IP."""
        return list(
            self.session.execute(
                select(InfrastructureModel).where(InfrastructureModel.ip == ip)
            ).scalars()
        )

    def get_by_asn(self, asn: str) -> list[InfrastructureModel]:
        """Find infrastructure records by ASN."""
        return list(
            self.session.execute(
                select(InfrastructureModel).where(InfrastructureModel.asn == asn)
            ).scalars()
        )


class FingerprintRepository:
    """CRUD operations for kit fingerprints."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, fingerprint_data: dict[str, Any], site_url: str = "") -> FingerprintModel:
        """Persist fingerprint record."""
        model = FingerprintModel(
            dom_hash=fingerprint_data.get("dom_hash", ""),
            asset_hash=fingerprint_data.get("asset_hash", ""),
            script_hash=fingerprint_data.get("script_hash", ""),
            campaign_fingerprint=fingerprint_data.get("campaign_fingerprint", ""),
            site_url=site_url,
        )
        self.session.add(model)
        self.session.flush()
        return model

    def get_by_campaign_fingerprint(self, fp: str) -> FingerprintModel | None:
        """Find fingerprint by campaign fingerprint hash."""
        return self.session.execute(
            select(FingerprintModel).where(FingerprintModel.campaign_fingerprint == fp)
        ).scalar_one_or_none()


class MISPEventRepository:
    """CRUD operations for MISP event tracking."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create(
        self, event_uuid: str, event_id: int, site_url: str = "", campaign_id: str = ""
    ) -> MISPEventModel:
        """Record MISP event export."""
        model = MISPEventModel(
            event_uuid=event_uuid,
            event_id=event_id,
            site_url=site_url,
            campaign_id=campaign_id,
        )
        self.session.add(model)
        self.session.flush()
        return model

    def get_by_uuid(self, event_uuid: str) -> MISPEventModel | None:
        """Retrieve MISP event by UUID."""
        return self.session.execute(
            select(MISPEventModel).where(MISPEventModel.event_uuid == event_uuid)
        ).scalar_one_or_none()


def generate_campaign_id() -> str:
    """Generate unique campaign identifier."""
    return f"CAMP-{uuid.uuid4().hex[:12].upper()}"
