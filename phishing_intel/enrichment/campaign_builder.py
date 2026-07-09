"""
Campaign builder for persistence and enrichment.

Assembles campaign entities from analysis results and attribution,
persisting to database and preparing MISP export packages.

Architectural Responsibility:
    Orchestrates campaign lifecycle: creation, update, persistence,
    and MISP enrichment packaging.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog

from phishing_intel.database.repositories import (
    CampaignRepository,
    CertificateRepository,
    FingerprintRepository,
    InfrastructureRepository,
    MISPEventRepository,
    PhishingSiteRepository,
)
from phishing_intel.database.session import get_session
from phishing_intel.enrichment.misp_client import MISPClient
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.campaign import Campaign
from phishing_intel.models.campaign import CampaignAttribution
from phishing_intel.models.findings import AnalysisResult

logger = structlog.get_logger(__name__)


class CampaignBuilder:
    """
    Campaign assembly, persistence, and MISP export orchestrator.

    Flow:
        1. Receive analysis result + attribution
        2. Persist site, certificate, infrastructure, fingerprint
        3. Create or update campaign record
        4. Export to MISP with taxonomy tags
        5. Record MISP event reference
    """

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialize campaign builder.

        Args:
            config: Platform configuration.
        """
        self.config = config
        self.misp_client = MISPClient(config)
        self.taxonomy_mapper = TaxonomyMapper()

    def build_and_persist(
        self,
        result: AnalysisResult,
        attribution: CampaignAttribution,
    ) -> Campaign:
        """
        Build campaign entity and persist all related records.

        Args:
            result: Complete analysis result.
            attribution: Campaign attribution from correlator.

        Returns:
            Persisted Campaign entity.
        """
        logger.info(
            "campaign_build_start",
            campaign_id=attribution.campaign_id,
            url=result.url,
        )

        with get_session() as session:
            site_repo = PhishingSiteRepository(session)
            cert_repo = CertificateRepository(session)
            infra_repo = InfrastructureRepository(session)
            fp_repo = FingerprintRepository(session)
            campaign_repo = CampaignRepository(session)

            # Persist phishing site
            site_repo.create(result, attribution.campaign_id)

            # Persist certificate
            if result.ssl:
                cert_repo.create(result.ssl.model_dump(), result.url)

            # Persist infrastructure
            if result.infrastructure:
                infra_repo.create(result.infrastructure.model_dump())

            # Persist fingerprint (update site_url if fingerprint already exists)
            existing_fp = fp_repo.get_by_campaign_fingerprint(
                result.kit_fingerprint.campaign_fingerprint
            )
            if not existing_fp:
                fp_repo.create(result.kit_fingerprint.model_dump(), result.url)
            elif not existing_fp.site_url:
                existing_fp.site_url = result.url
                session.flush()

            # Create or update campaign
            existing = campaign_repo.get_by_id(attribution.campaign_id)
            if existing:
                campaign_repo.update_score(
                    attribution.campaign_id,
                    attribution.score,
                    attribution.confidence.value,
                )
                incident_count = existing.incident_count + 1
            else:
                incident_count = 1

            tags = self.taxonomy_mapper.map_tags(result, attribution)

            campaign = Campaign(
                campaign_id=attribution.campaign_id,
                name=f"Phishing: {result.brand.brand if result.brand else result.url}",
                attribution=attribution,
                target_brand=result.brand.brand if result.brand else "",
                phishing_type=result.phishing_type.value,
                kit_fingerprint=result.kit_fingerprint.campaign_fingerprint,
                incident_count=incident_count,
                tags=tags,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            if not existing:
                campaign_repo.create(campaign)

        logger.info("campaign_build_complete", campaign_id=attribution.campaign_id)
        return campaign

    def export_to_misp(
        self,
        result: AnalysisResult,
        attribution: CampaignAttribution,
    ) -> dict[str, Any] | None:
        """
        Export analysis to MISP and record event reference.

        Args:
            result: Analysis result.
            attribution: Campaign attribution.

        Returns:
            MISP event data or None.
        """
        tags = self.taxonomy_mapper.map_tags(result, attribution)
        event_data = self.misp_client.create_event(result, attribution, tags)

        if event_data and not event_data.get("mock"):
            with get_session() as session:
                misp_repo = MISPEventRepository(session)
                misp_repo.create(
                    event_uuid=event_data.get("uuid", ""),
                    event_id=event_data.get("id", 0),
                    site_url=result.url,
                    campaign_id=attribution.campaign_id,
                )

        return event_data
