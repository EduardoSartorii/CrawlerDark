"""
MISP integration client via PyMISP.

Creates events, attributes, and custom phishing-campaign objects
for threat intelligence sharing with CTI partners.

Architectural Responsibility:
    Export layer translating analysis results into MISP data model
    for community threat intelligence sharing.

MISP Objects Created:
    - domain, url, ip, x509, file, http-request (standard)
    - phishing-campaign (custom object)
"""

from __future__ import annotations

from typing import Any

import structlog

from phishing_intel.models.campaign import CampaignAttribution
from phishing_intel.models.findings import AnalysisResult

logger = structlog.get_logger(__name__)


class MISPClient:
    """
    PyMISP wrapper for phishing intelligence export.

    Handles event creation, attribute population, and custom
    phishing-campaign object generation.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        """
        Initialize MISP client.

        Args:
            config: MISP connection configuration.
        """
        self.config = config.get("misp", {})
        self.url = self.config.get("url", "")
        self.api_key = self.config.get("api_key", "")
        self.verify_ssl = self.config.get("verify_ssl", True)
        self._misp = None

    def _get_client(self) -> Any:
        """Lazy-load PyMISP client."""
        if self._misp is None:
            if not self.api_key:
                logger.warning("misp_api_key_missing")
                return None
            try:
                from pymisp import PyMISP

                self._misp = PyMISP(
                    self.url,
                    self.api_key,
                    self.verify_ssl,
                )
            except ImportError:
                logger.error("pymisp_not_installed")
                return None
            except Exception as exc:
                logger.error("misp_connection_failed", error=str(exc))
                return None
        return self._misp

    def create_event(
        self,
        result: AnalysisResult,
        attribution: CampaignAttribution,
        tags: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Create MISP event from analysis result.

        Args:
            result: Complete analysis result.
            attribution: Campaign attribution data.
            tags: MISP tags to apply.

        Returns:
            Created event data or None on failure.
        """
        misp = self._get_client()
        if misp is None:
            return self._mock_event(result, attribution, tags)

        logger.info("misp_event_creation_start", url=result.url)

        try:
            from pymisp import MISPEvent

            event = MISPEvent()
            event.info = f"Phishing: {result.brand.brand if result.brand else result.url}"
            event.distribution = self.config.get("default_distribution", 1)
            event.threat_level_id = self.config.get("default_threat_level", 2)
            event.analysis = self.config.get("default_analysis", 1)

            # Add tags
            for tag in tags or []:
                event.add_tag(tag)

            # Add attributes
            self._add_attributes(event, result)

            # Add custom phishing-campaign object
            self._add_campaign_object(event, result, attribution)

            created = misp.add_event(event)
            event_data = {
                "uuid": created.get("Event", {}).get("uuid", ""),
                "id": created.get("Event", {}).get("id", 0),
            }

            logger.info(
                "misp_event_created",
                event_uuid=event_data["uuid"],
                event_id=event_data["id"],
            )
            return event_data

        except Exception as exc:
            logger.error("misp_event_creation_failed", error=str(exc))
            return None

    def _add_attributes(self, event: Any, result: AnalysisResult) -> None:
        """Add standard MISP attributes from analysis IOCs."""
        # URL attribute
        event.add_attribute("url", result.url, category="Network activity")

        # Domain
        from phishing_intel.utils import extract_domain

        domain = extract_domain(result.url)
        event.add_attribute("domain", domain, category="Network activity")

        # IPs
        for ip in result.iocs.ips:
            event.add_attribute("ip-dst", ip, category="Network activity")

        # Exfiltration URLs
        for dest in result.exfiltration.destinations:
            event.add_attribute("url", dest.url, category="Network activity",
                                comment=f"Exfiltration: {dest.exfiltration_type.value}")

        # SSL certificate
        if result.ssl:
            event.add_attribute(
                "x509-fingerprint-sha1",
                result.ssl.sha1_fingerprint,
                category="Payload delivery",
            )

        # File hashes
        if result.html_hash:
            event.add_attribute("sha256", result.html_hash, category="Artifacts",
                                comment="HTML content hash")
        if result.javascript.script_hash:
            event.add_attribute("sha256", result.javascript.script_hash,
                                category="Artifacts", comment="JavaScript hash")

    def _add_campaign_object(
        self,
        event: Any,
        result: AnalysisResult,
        attribution: CampaignAttribution,
    ) -> None:
        """Add custom phishing-campaign MISP object."""
        try:
            from pymisp import MISPObject

            obj = MISPObject("phishing-campaign")
            obj.add_attribute("campaign_id", attribution.campaign_id)
            obj.add_attribute("campaign_score", str(attribution.score))
            obj.add_attribute("confidence_level", attribution.confidence.value)
            obj.add_attribute(
                "kit_fingerprint", result.kit_fingerprint.campaign_fingerprint
            )

            if result.ssl:
                obj.add_attribute("ssl_fingerprint", result.ssl.sha256_fingerprint)
                obj.add_attribute("ssl_serial", result.ssl.serial_number)

            if result.brand:
                obj.add_attribute("target_brand", result.brand.brand)

            obj.add_attribute("phishing_type", result.phishing_type.value)

            if result.infrastructure:
                obj.add_attribute("hosting_provider", result.infrastructure.hosting_provider)
                obj.add_attribute("asn", result.infrastructure.asn)

            event.add_object(obj)
        except Exception as exc:
            logger.warning("misp_campaign_object_failed", error=str(exc))

    def _mock_event(
        self,
        result: AnalysisResult,
        attribution: CampaignAttribution,
        tags: list[str] | None,
    ) -> dict[str, Any]:
        """Generate mock event data when MISP is unavailable."""
        import uuid

        mock_uuid = str(uuid.uuid4())
        logger.info("misp_mock_event_created", uuid=mock_uuid)
        return {"uuid": mock_uuid, "id": 0, "mock": True}
