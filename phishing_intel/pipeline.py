"""End-to-end analysis pipeline (orchestrator).

Component responsibility
------------------------
Wire every layer of the platform into a single, testable pipeline:

``analyze(sample)`` (primary, offline flow)
    HTML/JS -> DOM -> classification -> JS -> exfiltration -> fingerprint ->
    brand -> (optional SSL/DNS/infra collection) -> multi-profile diff ->
    :class:`AnalysisResult`.

``process(sample)`` (full flow)
    ``analyze`` -> correlate against history -> persist -> map tags -> push to
    MISP -> preserve evidence -> return a :class:`PipelineOutcome`.

Design
------
Every network-facing collaborator (HTML/SSL/infra collectors, MISP client) is
injectable so the whole pipeline can run fully offline in tests and in
analysis-only deployments (``settings.app.allow_network = false``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter
from phishing_intel.collectors.html_collector import HTMLCollector
from phishing_intel.collectors.infrastructure_collector import (
    InfrastructureCollector,
)
from phishing_intel.collectors.ssl_collector import SSLCollector
from phishing_intel.config.settings import Settings
from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.database.repositories import AnalysisRepository
from phishing_intel.database.session import Database
from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.enrichment.misp_client import MISPEnricher
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.evidence import EvidenceStore
from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import AttributionScore
from phishing_intel.models.findings import AnalysisResult, PhishingSample
from phishing_intel.render_compare import RenderComparator
from phishing_intel.utils import dedupe_preserve_order, extract_domain, sha256_text

logger = get_logger(__name__)


@dataclass
class PipelineOutcome:
    """The complete result of processing a sample end-to-end."""

    result: AnalysisResult
    attribution: AttributionScore
    tags: List[str]
    campaign_id: Optional[str]
    misp_event_uuid: Optional[str]
    evidence_path: Optional[str]


class PhishingIntelPipeline:
    """Orchestrates analysis, correlation, persistence and enrichment."""

    def __init__(
        self,
        settings: Settings,
        database: Optional[Database] = None,
        *,
        html_collector: Optional[HTMLCollector] = None,
        ssl_collector: Optional[SSLCollector] = None,
        infrastructure_collector: Optional[InfrastructureCollector] = None,
        misp_enricher: Optional[MISPEnricher] = None,
    ) -> None:
        self.settings = settings

        # Analyzers (pure, offline).
        self.dom_analyzer = DOMAnalyzer()
        self.form_classifier = FormClassifier()
        self.js_analyzer = JavaScriptAnalyzer()
        self.exfil_analyzer = ExfiltrationAnalyzer()
        self.fingerprinter = KitFingerprinter()
        self.brand_detector = BrandDetector()
        self.render_comparator = RenderComparator(self.dom_analyzer)

        # Collectors (network; injectable + gated by allow_network).
        self.html_collector = html_collector or HTMLCollector()
        self.ssl_collector = ssl_collector or SSLCollector()
        self.infra_collector = infrastructure_collector or InfrastructureCollector()

        # Persistence.
        self.database = database

        # Enrichment.
        self.taxonomy = TaxonomyMapper()
        self.campaign_builder = CampaignBuilder()
        self.misp = misp_enricher or MISPEnricher(settings.misp)

        # Evidence store (chain of custody).
        self.evidence = EvidenceStore(settings.app.evidence_dir)

    # ------------------------------------------------------------------
    # Primary flow: analysis
    # ------------------------------------------------------------------
    def analyze(self, sample: PhishingSample) -> AnalysisResult:
        """Run the offline-first static analysis of a sample.

        Implements both the primary flow (artifacts provided) and the secondary
        flow (fetch HTML when missing and network is permitted).
        """

        domain = extract_domain(sample.url)

        # --- Secondary flow: obtain HTML if the partner did not supply it ---
        html = sample.html
        if not html and self.settings.app.allow_network:
            logger.info("pipeline.collect_html", url=sample.url)
            html = self.html_collector.collect(sample.url)
        html = html or ""

        # --- DOM analysis ---------------------------------------------------
        dom = self.dom_analyzer.analyze(html, sample.url)

        # --- Phishing objective classification -----------------------------
        classification = self.form_classifier.classify(dom)

        # --- JavaScript analysis (inline + partner-provided files) ----------
        scripts = list(dom.scripts_inline) + list(sample.javascript)
        js = self.js_analyzer.analyze(scripts)

        # --- Exfiltration analysis -----------------------------------------
        exfil = self.exfil_analyzer.analyze(dom, js)

        # --- Kit fingerprinting --------------------------------------------
        fingerprint = self.fingerprinter.fingerprint(dom)

        # --- Brand detection ------------------------------------------------
        brand = self.brand_detector.detect(dom, sample.url)

        # --- Hashes for the evidence chain ---------------------------------
        html_hash = sha256_text(html) if html else None
        javascript_hash = sha256_text("\n".join(scripts)) if scripts else None

        result = AnalysisResult(
            url=sample.url,
            domain=domain,
            html_hash=html_hash,
            javascript_hash=javascript_hash,
            dom=dom,
            classification=classification,
            javascript=js,
            exfiltration=exfil,
            fingerprint=fingerprint,
            brand=brand,
        )

        # --- Optional live enrichment (SSL / DNS / infrastructure) ----------
        if self.settings.app.allow_network and domain:
            self._enrich_infrastructure(result, domain)

        # --- Multi-profile render comparison -------------------------------
        if self.settings.app.allow_network and self.settings.render_profiles:
            self._compare_profiles(result, sample.url)

        # --- IOC aggregation ------------------------------------------------
        result.iocs = self._collect_iocs(result)

        logger.info(
            "pipeline.analyzed",
            url=sample.url,
            phishing_type=classification.primary_type.value,
            brand=brand.target_brand,
            iocs=len(result.iocs),
        )
        return result

    def _enrich_infrastructure(self, result: AnalysisResult, domain: str) -> None:
        """Collect SSL + hosting infrastructure and attach to the result."""

        try:
            result.certificate = self.ssl_collector.collect(domain)
        except Exception as exc:  # noqa: BLE001 - never let collection break analysis
            logger.warning("pipeline.ssl_error", domain=domain, error=str(exc))
        try:
            result.infrastructure = self.infra_collector.collect(domain)
        except Exception as exc:  # noqa: BLE001
            logger.warning("pipeline.infra_error", domain=domain, error=str(exc))

    def _compare_profiles(self, result: AnalysisResult, url: str) -> None:
        """Fetch the page across render profiles and store the diffs."""

        try:
            profile_htmls = self.html_collector.collect_profiles(
                url, self.settings.render_profiles
            )
            result.render_diffs = self.render_comparator.compare(profile_htmls, url)
        except Exception as exc:  # noqa: BLE001
            logger.warning("pipeline.render_error", url=url, error=str(exc))

    def _collect_iocs(self, result: AnalysisResult) -> List[str]:
        """Aggregate and de-duplicate every IOC surfaced during analysis."""

        iocs: List[str] = [result.url]
        if result.domain:
            iocs.append(result.domain)
        if result.dom:
            iocs.extend(result.dom.external_urls)
        if result.javascript:
            iocs.extend(result.javascript.hardcoded_urls)
            iocs.extend(result.javascript.external_resources)
        if result.exfiltration:
            iocs.extend(d.destination for d in result.exfiltration.destinations)
        if result.infrastructure and result.infrastructure.ip:
            iocs.append(result.infrastructure.ip)
        return dedupe_preserve_order(iocs)

    # ------------------------------------------------------------------
    # Full flow: analyze + correlate + persist + enrich
    # ------------------------------------------------------------------
    def process(self, sample: PhishingSample) -> PipelineOutcome:
        """Run the complete pipeline for a sample.

        Returns
        -------
        PipelineOutcome
            The analysis result plus attribution, tags, campaign id, MISP event
            reference and evidence path.
        """

        result = self.analyze(sample)

        attribution = AttributionScore()
        campaign_id: Optional[str] = None

        # --- Correlation + persistence (requires a database) ---------------
        if self.database is not None:
            with self.database.session_scope() as session:
                repo = AnalysisRepository(session)
                correlator = CampaignCorrelator(repo.sites, self.settings.correlation)
                attribution = correlator.correlate(result)
                campaign_id = attribution.matched_campaign_id
                repo.save_analysis(result, campaign_id=campaign_id)

        # --- Tags -----------------------------------------------------------
        tags = self.taxonomy.map_tags(result, attribution)

        # --- MISP enrichment ------------------------------------------------
        misp_uuid: Optional[str] = None
        try:
            misp_uuid, misp_id = self.misp.push(result, attribution, tags)
            if misp_uuid and self.database is not None:
                # Record the created MISP event reference.
                with self.database.session_scope() as session:
                    AnalysisRepository(session).misp_events.record(
                        result.url, misp_uuid, misp_id or ""
                    )
        except Exception as exc:  # noqa: BLE001 - MISP outages must not fail analysis
            logger.warning("pipeline.misp_error", url=sample.url, error=str(exc))

        # --- Evidence preservation -----------------------------------------
        scripts = list(result.dom.scripts_inline) if result.dom else []
        scripts.extend(sample.javascript)
        evidence_path = str(self.evidence.store(result, sample.html, scripts))

        outcome = PipelineOutcome(
            result=result,
            attribution=attribution,
            tags=tags,
            campaign_id=campaign_id,
            misp_event_uuid=misp_uuid,
            evidence_path=evidence_path,
        )
        logger.info(
            "pipeline.processed",
            url=sample.url,
            score=attribution.score,
            confidence=attribution.confidence.value,
            campaign_id=campaign_id,
            misp_event=misp_uuid,
        )
        return outcome
