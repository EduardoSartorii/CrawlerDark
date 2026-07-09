"""Repository abstractions for database read/write operations."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishing_intel.database.models import (
    Campaign,
    Certificate,
    EvidenceAudit,
    Fingerprint,
    Infrastructure,
    MispEvent,
    PhishingSite,
    ProfileComparison,
)


class CampaignRepository:
    """Persistence gateway for campaign entities."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_campaign(self, campaign_id: str, score: int, confidence: str) -> Campaign:
        """Persist a campaign entry and return the ORM object."""

        campaign = Campaign(campaign_id=campaign_id, score=score, confidence=confidence)
        self.session.add(campaign)
        self.session.commit()
        self.session.refresh(campaign)
        return campaign

    def list_by_brand_confidence(self, confidence: str) -> list[Campaign]:
        """Return campaigns filtered by confidence level."""

        query = select(Campaign).where(Campaign.confidence == confidence)
        return list(self.session.scalars(query))


class SiteRepository:
    """Persistence gateway for phishing site evidence."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_site(
        self, url: str, domain: str, html_hash: str, javascript_hash: str | None, campaign_db_id: int | None
    ) -> PhishingSite:
        """Persist one analyzed phishing site."""

        site = PhishingSite(
            url=url,
            domain=domain,
            html_hash=html_hash,
            javascript_hash=javascript_hash,
            campaign_id_fk=campaign_db_id,
        )
        self.session.add(site)
        self.session.commit()
        self.session.refresh(site)
        return site


class InfrastructureRepository:
    """Persistence gateway for infrastructure metadata."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_infrastructure(
        self, domain: str, ip: str, asn: str | None, provider: str | None, organization: str | None, country: str | None
    ) -> Infrastructure:
        """Persist one infrastructure profile."""

        item = Infrastructure(
            domain=domain,
            ip=ip,
            asn=asn,
            provider=provider,
            organization=organization,
            country=country,
        )
        self.session.add(item)
        self.session.commit()
        self.session.refresh(item)
        return item


class CertificateRepository:
    """Persistence gateway for SSL certificate metadata."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_certificate(
        self,
        serial_number: str,
        issuer: str,
        fingerprint: str,
        subject: str,
        san: list[str],
        not_before: str,
        not_after: str,
        pem: str,
    ) -> Certificate:
        """Persist normalized certificate details."""

        cert = Certificate(
            serial_number=serial_number,
            issuer=issuer,
            fingerprint=fingerprint,
            subject=subject,
            san=san,
            not_before=not_before,
            not_after=not_after,
            pem=pem,
        )
        self.session.add(cert)
        self.session.commit()
        self.session.refresh(cert)
        return cert


class FingerprintRepository:
    """Persistence gateway for fingerprint entities."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_fingerprint(
        self, dom_hash: str, asset_hash: str, script_hash: str, campaign_fingerprint: str
    ) -> Fingerprint:
        """Persist a fingerprint tuple for future campaign matching."""

        fp = Fingerprint(
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            campaign_fingerprint=campaign_fingerprint,
        )
        self.session.add(fp)
        self.session.commit()
        self.session.refresh(fp)
        return fp

    def find_by_campaign_fingerprint(self, campaign_fingerprint: str) -> list[Fingerprint]:
        """List records sharing the same campaign fingerprint."""

        query = select(Fingerprint).where(Fingerprint.campaign_fingerprint == campaign_fingerprint)
        return list(self.session.scalars(query))


class MispEventRepository:
    """Persistence gateway for MISP event mappings."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_event_mapping(self, event_uuid: str, event_id: str, campaign_id: str) -> MispEvent:
        """Persist local mapping between campaign and MISP event."""

        event = MispEvent(event_uuid=event_uuid, event_id=event_id, campaign_id=campaign_id)
        self.session.add(event)
        self.session.commit()
        self.session.refresh(event)
        return event


class EvidenceRepository:
    """Persistence gateway for chain-of-custody records."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def store_audit(
        self,
        timestamp,
        url: str,
        html_hash: str,
        javascript_hash: str | None,
        ssl_fingerprint: str | None,
        raw_html: str,
        raw_javascript: list[str],
        analysis_result: dict[str, str | int | float | list[str]],
    ) -> EvidenceAudit:
        """Persist one immutable evidence audit record."""

        record = EvidenceAudit(
            timestamp=timestamp,
            url=url,
            html_hash=html_hash,
            javascript_hash=javascript_hash,
            ssl_fingerprint=ssl_fingerprint,
            raw_html=raw_html,
            raw_javascript=raw_javascript,
            analysis_result=analysis_result,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record


class ProfileComparisonRepository:
    """Persistence gateway for multi-profile DOM/script comparison."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def store_comparison(
        self,
        url: str,
        profile_name: str,
        dom_hash: str,
        asset_hash: str,
        script_hash: str,
        dom_diff: dict[str, list[str]],
    ) -> ProfileComparison:
        """Persist one rendering-profile comparison snapshot."""

        item = ProfileComparison(
            url=url,
            profile_name=profile_name,
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            dom_diff=dom_diff,
        )
        self.session.add(item)
        self.session.commit()
        self.session.refresh(item)
        return item
