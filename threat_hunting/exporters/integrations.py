"""External CTI/SIEM exporter adapters.

Adapters keep third-party integration details outside the core. Network-heavy
exporters are intentionally small and can be replaced with async or queue-based
implementations without changing the pipeline.
"""

from __future__ import annotations

from typing import Any

import httpx

from threat_hunting.core.domain.entities import Finding


class WebhookExporter:
    """POST canonical findings to a webhook or REST API."""

    name = "webhook"

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._headers = headers or {}

    def export(self, finding: Finding) -> None:
        """Send one finding as JSON."""

        response = httpx.post(self._url, json=finding.model_dump(mode="json"), headers=self._headers, timeout=30.0)
        response.raise_for_status()


class MispExporter:
    """Export findings to MISP using PyMISP when configured."""

    name = "misp"

    def __init__(self, url: str, api_key: str, event_id: str, verify_tls: bool = True) -> None:
        from pymisp import ExpandedPyMISP, MISPObject

        self._misp = ExpandedPyMISP(url, api_key, verify_tls)
        self._event_id = event_id
        self._object_class = MISPObject

    def export(self, finding: Finding) -> None:
        """Create a MISP object with finding indicators and context."""

        misp_object = self._object_class(name="threat-hunting-finding")
        misp_object.add_attribute("text", value=finding.title)
        misp_object.add_attribute("comment", value=finding.description)
        for indicator in finding.indicators:
            misp_object.add_attribute(indicator.type.value, value=indicator.value)
        self._misp.add_object(self._event_id, misp_object)


class PlaceholderExternalExporter:
    """Adapter placeholder for Splunk, OpenSearch, OpenCTI, TAXII and SIEM sinks."""

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name = name
        self.config = config
        self.exported: list[str] = []

    def export(self, finding: Finding) -> None:
        """Record export intent for integrations that need environment-specific clients."""

        self.exported.append(finding.id)
