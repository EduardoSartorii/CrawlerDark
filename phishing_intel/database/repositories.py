"""Repository layer for campaign history and audit persistence."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishing_intel.database.models import (
    CampaignORM,
    CertificateORM,
    FingerprintORM,
    InfrastructureORM,
    MispEventORM,
    PhishingSiteORM,
)
from phishing_intel.models.findings import AnalysisResult
from phishing_intel.models.infrastructure import CertificateFinding, InfrastructureFinding


class CampaignRepository:
    """Persist and retrieve campaign intelligence records."""

    def __init__(self, session: Session) -> None:
        """Create a repository bound to a SQLAlchemy session."""

        self.session = session

    def save_analysis(
        self,
        result: AnalysisResult,
        infrastructure: InfrastructureFinding | None = None,
        certificate: CertificateFinding | None = None,
    ) -> CampaignORM:
        """Persist a complete analysis result and related CTI signals."""

        campaign = self._get_or_create_campaign(result.campaign_id, result.attribution_score, result.confidence)
        self.session.add(
            PhishingSiteORM(
                campaign=campaign,
                url=result.url,
                domain=result.domain,
                html_hash=result.html_hash,
                javascript_hash=result.javascript_hash,
                phishing_type=result.classification.phishing_type,
                target_brand=result.brand.target_brand,
            )
        )
        self.session.add(
            FingerprintORM(
                dom_hash=result.fingerprint.dom_sha256,
                asset_hash=result.fingerprint.asset_sha256,
                script_hash=result.fingerprint.script_sha256,
                campaign_fingerprint=result.fingerprint.campaign_fingerprint,
            )
        )
        if infrastructure:
            self.session.add(
                InfrastructureORM(
                    ip=infrastructure.ip,
                    asn=infrastructure.asn,
                    provider=infrastructure.hosting_provider,
                    organization=infrastructure.organization,
                    country=infrastructure.country,
                )
            )
        if certificate:
            self.session.add(
                CertificateORM(
                    serial_number=certificate.serial_number,
                    issuer=certificate.issuer,
                    fingerprint=certificate.sha256_fingerprint,
                    pem=certificate.pem,
                )
            )
        return campaign

    def save_misp_event(self, event_uuid: str | None, event_id: str | None) -> None:
        """Persist a MISP event reference for audit and replay tracking."""

        self.session.add(MispEventORM(event_uuid=event_uuid, event_id=event_id))

    def historical_signals(self) -> list[dict[str, str | None]]:
        """Return historical correlation signals from persisted records."""

        rows = self.session.execute(select(FingerprintORM)).scalars().all()
        return [
            {
                "dom_hash": row.dom_hash,
                "asset_hash": row.asset_hash,
                "script_hash": row.script_hash,
                "campaign_fingerprint": row.campaign_fingerprint,
            }
            for row in rows
        ]

    def _get_or_create_campaign(self, campaign_id: str, score: int, confidence: str) -> CampaignORM:
        """Fetch an existing campaign or create a new campaign row."""

        existing = self.session.execute(
            select(CampaignORM).where(CampaignORM.campaign_id == campaign_id)
        ).scalar_one_or_none()
        if existing:
            existing.score = max(existing.score, score)
            existing.confidence = confidence
            return existing
        campaign = CampaignORM(campaign_id=campaign_id, score=score, confidence=confidence)
        self.session.add(campaign)
        return campaign
