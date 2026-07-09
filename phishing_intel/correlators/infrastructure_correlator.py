"""Infrastructure correlator.

Component responsibility
------------------------
Compare the PKI/hosting facts of a new sample against history to detect reused
infrastructure. Emits weighted
:class:`~phishing_intel.models.campaign.CampaignMatch` signals.

Signals produced
----------------
* ``same_certificate`` - identical TLS certificate serial number (strong).
* ``same_asn``         - hosted on the same ASN (medium).
* ``same_provider``    - same hosting provider name (medium/weak).
"""

from __future__ import annotations

from typing import Dict, List

from phishing_intel.database.repositories import SiteRepository
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import CampaignMatch
from phishing_intel.models.findings import AnalysisResult

logger = get_logger(__name__)


class InfrastructureCorrelator:
    """Correlate a sample against history using PKI/hosting facts."""

    def __init__(self, site_repository: SiteRepository, weights: Dict[str, int]) -> None:
        self.sites = site_repository
        self.weights = weights

    def correlate(self, result: AnalysisResult) -> List[CampaignMatch]:
        """Return the infrastructure-based matches for ``result``."""

        matches: List[CampaignMatch] = []

        # --- Certificate reuse (serial number) -----------------------------
        cert = result.certificate
        if cert and cert.serial_number:
            hits = self.sites.find_by_cert_serial(cert.serial_number)
            if hits:
                matches.append(
                    CampaignMatch(
                        signal="same_certificate",
                        weight=self.weights.get("same_certificate", 25),
                        detail=f"{len(hits)} prior site(s) reused certificate serial {cert.serial_number}",
                    )
                )

        # --- Hosting reuse (ASN / provider) --------------------------------
        infra = result.infrastructure
        if infra and infra.asn:
            asn_hits = self.sites.find_by_asn(infra.asn)
            if asn_hits:
                matches.append(
                    CampaignMatch(
                        signal="same_asn",
                        weight=self.weights.get("same_asn", 15),
                        detail=f"{len(asn_hits)} prior site(s) hosted on ASN {infra.asn}",
                    )
                )
        if infra and infra.hosting_provider:
            provider_hits = [
                s
                for s in self.sites.list_all()
                if s.infrastructure and s.infrastructure.provider == infra.hosting_provider
            ]
            if provider_hits:
                matches.append(
                    CampaignMatch(
                        signal="same_provider",
                        weight=self.weights.get("same_provider", 10),
                        detail=f"{len(provider_hits)} prior site(s) on provider {infra.hosting_provider}",
                    )
                )

        logger.info("corr.infrastructure", matches=[m.signal for m in matches])
        return matches
