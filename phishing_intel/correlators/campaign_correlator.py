"""
Campaign correlation engine.

Correlates phishing incidents by fingerprint, certificate, ASN,
provider, DOM/JS patterns, and target brand to compute attribution scores.

Architectural Responsibility:
    Intelligence layer linking individual incidents into campaigns
    and computing operator attribution confidence.

Attribution Score Weights (configurable):
    - Same fingerprint: 35 (high)
    - Same certificate: 30 (high)
    - DOM pattern match: 20
    - JavaScript pattern match: 15
    - Same brand: 12 (medium)
    - Same ASN: 10 (medium)
    - Same provider: 8

Confidence Levels:
    0-39: Low | 40-69: Medium | 70-100: High
"""

from __future__ import annotations

from typing import Any

import structlog

from phishing_intel.database.repositories import (
    CampaignRepository,
    CertificateRepository,
    FingerprintRepository,
    InfrastructureRepository,
    PhishingSiteRepository,
    generate_campaign_id,
)
from phishing_intel.database.session import get_session
from phishing_intel.models.campaign import Campaign, CampaignAttribution, CorrelationSignal
from phishing_intel.models.findings import AnalysisResult, ConfidenceLevel

logger = structlog.get_logger(__name__)


class CampaignCorrelator:
    """
    Multi-signal campaign correlation and attribution engine.

    Compares new incident analysis against historical database
    to identify campaign membership and compute attribution score.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialize correlator with configurable weights.

        Args:
            config: Platform configuration with correlation weights.
        """
        self.weights = config.get("correlation", {}).get("weights", {})
        self.thresholds = config.get("correlation", {}).get("confidence_thresholds", {})

    def correlate(self, result: AnalysisResult) -> CampaignAttribution:
        """
        Correlate analysis result with historical incidents.

        Args:
            result: Complete analysis result for new incident.

        Returns:
            CampaignAttribution with score, confidence, and signals.
        """
        logger.info("campaign_correlation_start", url=result.url)

        signals: list[CorrelationSignal] = []
        related_incidents: list[str] = []
        matched_campaign_id: str | None = None

        with get_session() as session:
            fp_repo = FingerprintRepository(session)
            cert_repo = CertificateRepository(session)
            infra_repo = InfrastructureRepository(session)
            site_repo = PhishingSiteRepository(session)
            campaign_repo = CampaignRepository(session)

            # Fingerprint match (highest weight)
            fp = result.kit_fingerprint.campaign_fingerprint
            if fp:
                existing_fp = fp_repo.get_by_campaign_fingerprint(fp)
                if existing_fp:
                    weight = self.weights.get("fingerprint_match", 35)
                    signals.append(
                        CorrelationSignal(
                            signal_type="fingerprint_match",
                            weight=weight,
                            matched_value=fp,
                            description="Matching kit fingerprint",
                        )
                    )
                    related = site_repo.get_by_html_hash(result.html_hash)
                    related_incidents.extend([s.url for s in related])

            # Certificate match
            if result.ssl and result.ssl.sha1_fingerprint:
                certs = cert_repo.get_by_fingerprint(result.ssl.sha1_fingerprint)
                if certs:
                    weight = self.weights.get("certificate_match", 30)
                    signals.append(
                        CorrelationSignal(
                            signal_type="certificate_match",
                            weight=weight,
                            matched_value=result.ssl.sha1_fingerprint,
                            description="Matching SSL certificate",
                        )
                    )
                    related_incidents.extend([c.site_url for c in certs if c.site_url])

            # ASN match
            if result.infrastructure and result.infrastructure.asn:
                infra_records = infra_repo.get_by_asn(result.infrastructure.asn)
                if infra_records:
                    weight = self.weights.get("asn_match", 10)
                    signals.append(
                        CorrelationSignal(
                            signal_type="asn_match",
                            weight=weight,
                            matched_value=result.infrastructure.asn,
                            description="Same ASN hosting",
                        )
                    )

            # Brand match - find campaigns targeting same brand
            if result.brand:
                campaigns = campaign_repo.list_all(limit=500)
                for camp in campaigns:
                    if camp.target_brand == result.brand.brand:
                        weight = self.weights.get("brand_match", 12)
                        signals.append(
                            CorrelationSignal(
                                signal_type="brand_match",
                                weight=weight,
                                matched_value=result.brand.brand,
                                source_incident_id=camp.campaign_id,
                                description=f"Same target brand: {result.brand.brand}",
                            )
                        )
                        matched_campaign_id = camp.campaign_id
                        break

            # DOM pattern match
            if result.dom.structural_hash:
                sites = site_repo.get_by_html_hash(result.dom.structural_hash)
                if sites:
                    weight = self.weights.get("dom_pattern_match", 20)
                    signals.append(
                        CorrelationSignal(
                            signal_type="dom_pattern_match",
                            weight=weight,
                            matched_value=result.dom.structural_hash,
                            description="Matching DOM structure",
                        )
                    )
                    related_incidents.extend([s.url for s in sites])

            # JavaScript pattern match (network exfiltration indicators present)
            if result.javascript.script_hash and result.javascript.fetch_calls:
                weight = self.weights.get("javascript_pattern_match", 15)
                signals.append(
                    CorrelationSignal(
                        signal_type="javascript_pattern_match",
                        weight=weight,
                        matched_value=result.javascript.script_hash,
                        description="JavaScript exfiltration pattern detected",
                    )
                )

            # Use fingerprint-based campaign if found
            if not matched_campaign_id and fp:
                existing = fp_repo.get_by_campaign_fingerprint(fp)
                if existing:
                    sites = site_repo.get_by_url(existing.site_url)
                    if sites and sites.campaign_id:
                        matched_campaign_id = sites.campaign_id

        # Calculate score
        score = min(sum(s.weight for s in signals), 100.0)
        confidence = self._classify_confidence(score)

        campaign_id = matched_campaign_id or generate_campaign_id()

        attribution = CampaignAttribution(
            campaign_id=campaign_id,
            score=score,
            confidence=confidence,
            signals=signals,
            related_incidents=list(set(related_incidents)),
        )

        logger.info(
            "campaign_correlation_complete",
            campaign_id=campaign_id,
            score=score,
            confidence=confidence.value,
            signal_count=len(signals),
        )
        return attribution

    def _classify_confidence(self, score: float) -> ConfidenceLevel:
        """
        Classify attribution confidence from score.

        Business rules:
            0-39: Low confidence
            40-69: Medium confidence
            70-100: High confidence
        """
        low = self.thresholds.get("low", 39)
        medium = self.thresholds.get("medium", 69)

        if score <= low:
            return ConfidenceLevel.LOW
        elif score <= medium:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.HIGH
