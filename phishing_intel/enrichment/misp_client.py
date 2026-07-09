"""MISP enrichment client (PyMISP integration).

Component responsibility
------------------------
Turn an :class:`~phishing_intel.models.findings.AnalysisResult` (+ attribution
+ tags) into a fully-formed MISP event and push it via PyMISP. Builds standard
MISP objects (``domain``, ``url``, ``ip-dst``, ``x509``, ``file``,
``http-request``) plus a custom ``phishing-campaign`` object carrying the
attribution metadata.

Design
------
* PyMISP is imported lazily so the rest of the platform (and its tests) never
  require a live MISP server or the pymisp package at import time.
* ``build_event`` is a pure builder returning a ``MISPEvent`` graph; it is unit
  tested without any network. ``push`` performs the actual submission and is
  exercised with a mocked PyMISP client.
* A ``PyMISP``-like instance may be injected for testing.

Execution flow
--------------
``MISPEnricher.push(result, attribution, tags)`` -> ``build_event`` ->
``client.add_event`` -> return ``(event_uuid, event_id)``.
"""

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from phishing_intel.config.settings import MISPSettings
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import AttributionScore
from phishing_intel.models.findings import AnalysisResult

logger = get_logger(__name__)


def _import_pymisp() -> Any:
    """Lazily import pymisp, raising a clear error if it is unavailable."""

    try:
        import pymisp  # noqa: PLC0415 - intentional lazy import

        return pymisp
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "pymisp is required for MISP enrichment but is not installed."
        ) from exc


class MISPEnricher:
    """Create and push MISP events for analysed phishing samples."""

    def __init__(
        self,
        settings: MISPSettings,
        client: Optional[Any] = None,
    ) -> None:
        """Create the enricher.

        Parameters
        ----------
        settings:
            MISP connection + event defaults.
        client:
            Optional pre-built PyMISP-compatible client (injected in tests). When
            omitted a real ``PyMISP`` instance is created lazily on first use.
        """

        self.settings = settings
        self._client = client

    @property
    def client(self) -> Any:
        """Return (lazily creating) the PyMISP client."""

        if self._client is None:
            pymisp = _import_pymisp()
            self._client = pymisp.PyMISP(
                self.settings.url,
                self.settings.key,
                self.settings.verify_cert,
            )
        return self._client

    # -- Event construction --------------------------------------------------
    def build_event(
        self,
        result: AnalysisResult,
        attribution: Optional[AttributionScore] = None,
        tags: Optional[List[str]] = None,
    ) -> Any:
        """Build (but do not send) a ``MISPEvent`` graph for a sample.

        Returns a ``pymisp.MISPEvent`` populated with attributes, standard
        objects and the custom ``phishing-campaign`` object plus local tags.
        """

        pymisp = _import_pymisp()
        event = pymisp.MISPEvent()
        brand = result.brand.target_brand if result.brand else "unknown"
        event.info = f"Phishing campaign - {brand} - {result.domain or result.url}"
        event.distribution = self.settings.distribution
        event.threat_level_id = self.settings.threat_level_id
        event.analysis = self.settings.analysis

        # --- Core network attributes ---------------------------------------
        event.add_attribute("url", result.url, comment="Phishing URL")
        if result.domain:
            event.add_attribute("domain", result.domain, comment="Phishing domain")

        infra = result.infrastructure
        if infra and infra.ip:
            event.add_attribute("ip-dst", infra.ip, comment="Hosting IP")

        # --- file object (raw HTML hash) -----------------------------------
        if result.html_hash:
            file_obj = pymisp.MISPObject("file")
            file_obj.add_attribute("sha256", result.html_hash)
            file_obj.add_attribute("filename", f"{result.domain or 'page'}.html")
            event.add_object(file_obj)

        # --- x509 object (certificate) -------------------------------------
        cert = result.certificate
        if cert:
            x509_obj = pymisp.MISPObject("x509")
            if cert.serial_number:
                x509_obj.add_attribute("serial-number", cert.serial_number)
            if cert.issuer:
                x509_obj.add_attribute("issuer", cert.issuer)
            if cert.subject:
                x509_obj.add_attribute("subject", cert.subject)
            if cert.sha256_fingerprint:
                x509_obj.add_attribute("x509-fingerprint-sha256", cert.sha256_fingerprint)
            if cert.sha1_fingerprint:
                x509_obj.add_attribute("x509-fingerprint-sha1", cert.sha1_fingerprint)
            event.add_object(x509_obj)

        # --- http-request objects (exfiltration destinations) --------------
        if result.exfiltration:
            for dest in result.exfiltration.destinations:
                http_obj = pymisp.MISPObject("http-request")
                http_obj.add_attribute("url", dest.destination)
                http_obj.add_attribute(
                    "text",
                    f"channel={dest.channel.value};confidence={dest.confidence}",
                )
                event.add_object(http_obj)

        # --- Custom phishing-campaign object -------------------------------
        campaign_obj = self._build_campaign_object(pymisp, result, attribution)
        event.add_object(campaign_obj)

        # --- Tags -----------------------------------------------------------
        for tag in tags or []:
            event.add_tag(tag)

        logger.info(
            "misp.event_built",
            info=event.info,
            attributes=len(event.attributes),
            objects=len(event.objects),
            tags=len(tags or []),
        )
        return event

    def _build_campaign_object(
        self,
        pymisp: Any,
        result: AnalysisResult,
        attribution: Optional[AttributionScore],
    ) -> Any:
        """Build the custom ``phishing-campaign`` MISP object.

        ``strict=False`` lets us define the object's relations inline without a
        server-side template being registered, which keeps the platform
        self-contained while remaining compatible with a template when present.
        """

        obj = pymisp.MISPObject("phishing-campaign", strict=False)

        def add(relation: str, value: Any, attr_type: str = "text") -> None:
            """Add a relation only when a value is present.

            Because ``phishing-campaign`` is a custom object without a bundled
            template, PyMISP cannot infer attribute types; we therefore pass an
            explicit ``type`` for every relation (defaulting to ``text``).
            """

            if value is not None and value != "":
                obj.add_attribute(relation, value=str(value), type=attr_type)

        fingerprint = result.fingerprint.campaign_fingerprint if result.fingerprint else None
        cert = result.certificate
        infra = result.infrastructure

        add("campaign_id", attribution.matched_campaign_id if attribution else None)
        add("campaign_score", attribution.score if attribution else None, "counter")
        add("confidence_level", attribution.confidence.value if attribution else None)
        add("kit_fingerprint", fingerprint)
        add("ssl_fingerprint", cert.sha256_fingerprint if cert else None)
        add("ssl_serial", cert.serial_number if cert else None)
        add("target_brand", result.brand.target_brand if result.brand else None)
        add(
            "phishing_type",
            result.classification.primary_type.value if result.classification else None,
        )
        add("hosting_provider", infra.hosting_provider if infra else None)
        add("asn", infra.asn if infra else None)
        return obj

    # -- Submission ----------------------------------------------------------
    def push(
        self,
        result: AnalysisResult,
        attribution: Optional[AttributionScore] = None,
        tags: Optional[List[str]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Build and submit a MISP event.

        Returns
        -------
        Tuple[Optional[str], Optional[str]]
            ``(event_uuid, event_id)`` of the created event, or ``(None, None)``
            when MISP integration is disabled.
        """

        if not self.settings.enabled:
            logger.info("misp.disabled", url=result.url)
            return None, None

        event = self.build_event(result, attribution, tags)
        created = self.client.add_event(event, pythonify=True)

        # PyMISP returns either a MISPEvent (pythonify=True) or a dict.
        event_uuid = getattr(created, "uuid", None)
        event_id = getattr(created, "id", None)
        if event_uuid is None and isinstance(created, dict):
            payload = created.get("Event", created)
            event_uuid = payload.get("uuid")
            event_id = payload.get("id")

        logger.info("misp.event_pushed", event_uuid=event_uuid, event_id=event_id)
        return event_uuid, (str(event_id) if event_id is not None else None)
