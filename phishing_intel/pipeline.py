"""End-to-end phishing artifact analysis pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DomAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter
from phishing_intel.collectors.html_collector import HtmlCollector
from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.database.repositories import CampaignRepository
from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.enrichment.misp_client import MispClient
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.findings import AnalysisRequest, AnalysisResult
from phishing_intel.models.infrastructure import CertificateFinding, InfrastructureFinding
from phishing_intel.utils import extract_domain, extract_iocs, log_event, preserve_evidence, sha256_text


class PhishingIntelPipeline:
    """Coordinate collection, static analysis, correlation, persistence, and MISP."""

    def __init__(
        self,
        repository: CampaignRepository | None = None,
        evidence_path: Path = Path("evidence"),
        misp_client: MispClient | None = None,
    ) -> None:
        """Create a pipeline with injectable persistence and MISP integrations."""

        self.repository = repository
        self.evidence_path = evidence_path
        self.html_collector = HtmlCollector()
        self.dom_analyzer = DomAnalyzer()
        self.javascript_analyzer = JavaScriptAnalyzer()
        self.form_classifier = FormClassifier()
        self.exfiltration_analyzer = ExfiltrationAnalyzer()
        self.fingerprinter = KitFingerprinter()
        self.brand_detector = BrandDetector()
        self.correlator = CampaignCorrelator()
        self.taxonomy_mapper = TaxonomyMapper()
        self.campaign_builder = CampaignBuilder()
        self.misp_client = misp_client or MispClient(None, None, dry_run=True)
        self.logger = logging.getLogger(__name__)

    def analyze(
        self,
        request: AnalysisRequest,
        infrastructure: InfrastructureFinding | None = None,
        certificate: CertificateFinding | None = None,
        enrich_misp: bool = True,
    ) -> tuple[AnalysisResult, dict[str, object] | None]:
        """Run the full analysis workflow for supplied or collected artifacts."""

        html = request.html
        if not html and request.url and request.fetch_if_missing:
            html = self.html_collector.collect(request.url)
        html = html or ""
        javascript = request.javascript or ""
        dom = self.dom_analyzer.analyze(html, request.url)
        js = self.javascript_analyzer.analyze(javascript + "\n".join(dom.scripts))
        classification = self.form_classifier.classify(dom)
        exfiltration = self.exfiltration_analyzer.analyze(dom, js)
        brand = self.brand_detector.detect(dom, js, html)
        fingerprint = self.fingerprinter.fingerprint(dom, js)
        historical = self.repository.historical_signals() if self.repository else []
        attribution = self.correlator.correlate(fingerprint, dom, js, brand, infrastructure, certificate, historical)
        extracted_iocs = sorted(set(request.iocs) | set(extract_iocs(html, javascript, request.url)))
        result = AnalysisResult(
            url=request.url,
            domain=extract_domain(request.url),
            html_hash=sha256_text(html) if html else None,
            javascript_hash=sha256_text(javascript) if javascript else None,
            dom=dom,
            javascript=js,
            classification=classification,
            exfiltration=exfiltration,
            brand=brand,
            fingerprint=fingerprint,
            extracted_iocs=extracted_iocs,
            campaign_id=attribution.campaign_id,
            attribution_score=attribution.score,
            confidence=attribution.confidence,
        )
        self._preserve_artifacts(result, html, javascript)
        if self.repository:
            self.repository.save_analysis(result, infrastructure, certificate)
        misp_response = self._enrich_misp(result, infrastructure, certificate) if enrich_misp else None
        log_event(
            self.logger,
            "analysis_completed",
            campaign_id=result.campaign_id,
            score=result.attribution_score,
            iocs=len(result.extracted_iocs),
        )
        return result, misp_response

    def _preserve_artifacts(self, result: AnalysisResult, html: str, javascript: str) -> None:
        """Store raw artifacts and normalized analysis evidence."""

        if html:
            preserve_evidence(self.evidence_path, result.campaign_id, "raw.html", html)
        if javascript:
            preserve_evidence(self.evidence_path, result.campaign_id, "raw.js", javascript)
        preserve_evidence(self.evidence_path, result.campaign_id, "analysis.json", result.model_dump_json(indent=2))

    def _enrich_misp(
        self,
        result: AnalysisResult,
        infrastructure: InfrastructureFinding | None,
        certificate: CertificateFinding | None,
    ) -> dict[str, object]:
        """Build and submit a MISP event payload."""

        tags = self.taxonomy_mapper.tags_for(result)
        payload = self.campaign_builder.build(result, infrastructure, certificate, tags)
        response = self.misp_client.submit_event(payload)
        if self.repository and not response.get("dry_run"):
            event = response.get("event", {})
            self.repository.save_misp_event(event.get("uuid"), str(event.get("id")) if event.get("id") else None)
        return response
