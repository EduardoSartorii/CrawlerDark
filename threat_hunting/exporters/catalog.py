"""Catalog of concrete exporter classes for each destination type."""

from __future__ import annotations

from threat_hunting.exporters.generic import GenericExporter


class OpenCtiExporter(GenericExporter):
    """OpenCTI exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="opencti")


class SplunkExporter(GenericExporter):
    """Splunk exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="splunk")


class OpenSearchExporter(GenericExporter):
    """OpenSearch exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="opensearch")


class WebhookExporter(GenericExporter):
    """Webhook exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="webhook")


class RestApiExporter(GenericExporter):
    """REST API exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="rest")


class CsvExporter(GenericExporter):
    """CSV exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="csv")


class StixExporter(GenericExporter):
    """STIX 2.1 exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="stix")


class TaxiiExporter(GenericExporter):
    """TAXII 2.1 exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="taxii")


class ElasticExporter(GenericExporter):
    """Elastic exporter adapter."""

    def __init__(self) -> None:
        super().__init__(name="elastic")
