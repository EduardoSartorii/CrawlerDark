"""Repository layer (data-access abstraction).

Responsibility
--------------
Encapsulate every query/mutation against the ORM so the rest of the codebase
depends on intention-revealing methods (``find_by_fingerprint``,
``save_analysis``) rather than raw SQLAlchemy. This keeps persistence concerns
out of the analysis/correlation logic and makes those layers unit-testable.

Execution flow
--------------
Repositories are instantiated with an active :class:`~sqlalchemy.orm.Session`
(usually obtained from ``Database.session_scope``). The orchestrator uses
:class:`AnalysisRepository.save_analysis` to persist a complete
:class:`~phishing_intel.models.findings.AnalysisResult` in one call.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from phishing_intel.database.models import (
    Campaign,
    Certificate,
    Fingerprint,
    Infrastructure,
    MispEvent,
    PhishingSite,
)
from phishing_intel.models.findings import AnalysisResult


class CampaignRepository:
    """CRUD + lookup helpers for :class:`Campaign`."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_campaign_id(self, campaign_id: str) -> Optional[Campaign]:
        """Return the campaign with the given business id, or None."""

        stmt = select(Campaign).where(Campaign.campaign_id == campaign_id)
        return self.session.scalars(stmt).first()

    def upsert(
        self,
        campaign_id: str,
        *,
        target_brand: Optional[str] = None,
        phishing_type: Optional[str] = None,
        kit_fingerprint: Optional[str] = None,
        score: int = 0,
        confidence: str = "low",
    ) -> Campaign:
        """Create the campaign if absent, otherwise refresh its mutable fields.

        Business rule: a campaign's ``last_seen`` is bumped on every sighting
        and its score/confidence reflect the most recent (highest-signal)
        correlation.
        """

        campaign = self.get_by_campaign_id(campaign_id)
        now = datetime.now(timezone.utc)
        if campaign is None:
            campaign = Campaign(
                campaign_id=campaign_id,
                target_brand=target_brand,
                phishing_type=phishing_type,
                kit_fingerprint=kit_fingerprint,
                score=score,
                confidence=confidence,
                first_seen=now,
                last_seen=now,
            )
            self.session.add(campaign)
        else:
            campaign.last_seen = now
            if score >= campaign.score:
                campaign.score = score
                campaign.confidence = confidence
            campaign.target_brand = target_brand or campaign.target_brand
            campaign.phishing_type = phishing_type or campaign.phishing_type
            campaign.kit_fingerprint = kit_fingerprint or campaign.kit_fingerprint
        self.session.flush()
        return campaign

    def list_all(self) -> List[Campaign]:
        """Return every campaign."""

        return list(self.session.scalars(select(Campaign)).all())


class SiteRepository:
    """CRUD + correlation lookup helpers for :class:`PhishingSite`."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def find_by_fingerprint(self, campaign_fingerprint: str) -> List[PhishingSite]:
        """Return sites sharing the given composite kit fingerprint."""

        stmt = (
            select(PhishingSite)
            .join(Fingerprint)
            .where(Fingerprint.campaign_fingerprint == campaign_fingerprint)
        )
        return list(self.session.scalars(stmt).all())

    def find_by_cert_serial(self, serial_number: str) -> List[PhishingSite]:
        """Return sites that presented a certificate with this serial number."""

        stmt = (
            select(PhishingSite)
            .join(Certificate)
            .where(Certificate.serial_number == serial_number)
        )
        return list(self.session.scalars(stmt).all())

    def find_by_asn(self, asn: str) -> List[PhishingSite]:
        """Return sites hosted on the given ASN."""

        stmt = (
            select(PhishingSite)
            .join(Infrastructure)
            .where(Infrastructure.asn == asn)
        )
        return list(self.session.scalars(stmt).all())

    def find_by_brand(self, brand: str) -> List[PhishingSite]:
        """Return sites impersonating the given brand."""

        stmt = select(PhishingSite).where(PhishingSite.target_brand == brand)
        return list(self.session.scalars(stmt).all())

    def find_by_dom_hash(self, dom_hash: str) -> List[PhishingSite]:
        """Return sites sharing the given DOM structural hash."""

        stmt = (
            select(PhishingSite)
            .join(Fingerprint)
            .where(Fingerprint.dom_hash == dom_hash)
        )
        return list(self.session.scalars(stmt).all())

    def list_all(self) -> List[PhishingSite]:
        """Return every persisted site."""

        return list(self.session.scalars(select(PhishingSite)).all())


class MispEventRepository:
    """CRUD helpers for :class:`MispEvent`."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def record(self, url: str, event_uuid: str, event_id: str) -> MispEvent:
        """Persist a reference to a created MISP event."""

        event = MispEvent(url=url, event_uuid=event_uuid, event_id=str(event_id))
        self.session.add(event)
        self.session.flush()
        return event

    def get_by_uuid(self, event_uuid: str) -> Optional[MispEvent]:
        """Return the MISP event reference with the given UUID, or None."""

        stmt = select(MispEvent).where(MispEvent.event_uuid == event_uuid)
        return self.session.scalars(stmt).first()


class AnalysisRepository:
    """High-level facade that persists a full :class:`AnalysisResult`.

    Combines the child repositories so the orchestrator can persist an entire
    incident (site + fingerprint + certificate + infrastructure) atomically.
    """

    def __init__(self, session: Session) -> None:
        self.session = session
        self.campaigns = CampaignRepository(session)
        self.sites = SiteRepository(session)
        self.misp_events = MispEventRepository(session)

    def save_analysis(
        self,
        result: AnalysisResult,
        *,
        campaign_id: Optional[str] = None,
    ) -> PhishingSite:
        """Persist an :class:`AnalysisResult` and its child records.

        Parameters
        ----------
        result:
            The complete analysis to persist.
        campaign_id:
            Optional campaign business id to link this site to.

        Returns
        -------
        PhishingSite
            The persisted ORM row (with populated ``id``).
        """

        site = PhishingSite(
            url=result.url,
            domain=result.domain,
            html_hash=result.html_hash,
            javascript_hash=result.javascript_hash,
            target_brand=result.brand.target_brand if result.brand else None,
            phishing_type=(
                result.classification.primary_type.value
                if result.classification
                else None
            ),
            # Persist the whole result as JSON for lossless retrieval.
            result_json=result.model_dump_json(),
        )

        # Attach the kit fingerprint child row.
        if result.fingerprint is not None:
            site.fingerprint = Fingerprint(
                dom_hash=result.fingerprint.dom_hash,
                asset_hash=result.fingerprint.asset_hash,
                script_hash=result.fingerprint.script_hash,
                campaign_fingerprint=result.fingerprint.campaign_fingerprint,
            )

        # Attach the certificate child row.
        if result.certificate is not None:
            site.certificate = Certificate(
                serial_number=result.certificate.serial_number,
                issuer=result.certificate.issuer,
                subject=result.certificate.subject,
                fingerprint=result.certificate.sha256_fingerprint,
            )

        # Attach the infrastructure child row.
        if result.infrastructure is not None:
            site.infrastructure = Infrastructure(
                ip=result.infrastructure.ip,
                asn=result.infrastructure.asn,
                provider=result.infrastructure.hosting_provider,
                country=result.infrastructure.country,
            )

        # Link to a campaign when supplied.
        if campaign_id is not None:
            campaign = self.campaigns.upsert(
                campaign_id,
                target_brand=site.target_brand,
                phishing_type=site.phishing_type,
                kit_fingerprint=(
                    result.fingerprint.campaign_fingerprint
                    if result.fingerprint
                    else None
                ),
            )
            site.campaign = campaign

        self.session.add(site)
        self.session.flush()
        return site
