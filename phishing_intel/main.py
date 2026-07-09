"""
Phishing Intelligence Platform - Main Orchestrator.

Entry point coordinating the complete analysis pipeline:

Primary Flow (partner-provided artifacts):
    1. Receive URL + HTML + JavaScript
    2. Store evidence
    3. Run static analysis (DOM, JS, forms, exfiltration, kit, brand)
    4. Collect infrastructure/SSL metadata
    5. Correlate with historical campaigns
    6. Persist and enrich MISP

Secondary Flow (collection required):
    1. Receive URL only
    2. Collect HTML via HTMLCollector
    3. Continue with primary flow

Architectural Responsibility:
    Pipeline orchestration, OPSEC evidence chain, and audit logging.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import structlog

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DOMAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprinter
from phishing_intel.collectors.html_collector import HTMLCollector
from phishing_intel.collectors.infrastructure_collector import InfrastructureCollector
from phishing_intel.collectors.ssl_collector import SSLCollector
from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.database.session import init_db
from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.models.findings import (
    AnalysisResult,
    IOCFinding,
    ProfileDiff,
    RenderProfile,
)
from phishing_intel.utils import (
    AuditLogger,
    EvidenceStore,
    load_config,
    setup_logging,
    sha256_hash,
    utc_now,
)

logger = structlog.get_logger(__name__)


class PhishingIntelPlatform:
    """
    Main platform orchestrator for phishing threat intelligence.

    Coordinates collectors, analyzers, correlators, and enrichment
    modules in the analysis pipeline with full evidence preservation.
    """

    def __init__(self, config_path: str | None = None) -> None:
        """
        Initialize platform with configuration.

        Args:
            config_path: Optional path to config.yaml.
        """
        self.config = load_config(config_path)

        # Setup logging
        log_config = self.config.get("logging", {})
        setup_logging(
            level=log_config.get("level", "INFO"),
            log_format=log_config.get("format", "json"),
        )

        # Initialize database
        db_config = self.config.get("database", {})
        init_db(
            db_config.get("url", "sqlite:///./phishing_intel.db"),
            echo=db_config.get("echo", False),
        )

        # Evidence and audit
        evidence_path = self.config.get("evidence", {}).get("storage_path", "./evidence")
        audit_path = self.config.get("audit", {}).get("storage_path", "./audit")
        self.evidence_store = EvidenceStore(evidence_path)
        self.audit_logger = AuditLogger(audit_path)

        # Initialize components
        self.html_collector = HTMLCollector(self.config, self.evidence_store)
        self.ssl_collector = SSLCollector()
        self.infra_collector = InfrastructureCollector()
        self.dom_analyzer = DOMAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.form_classifier = FormClassifier()
        self.exfil_analyzer = ExfiltrationAnalyzer()
        self.kit_fingerprinter = KitFingerprinter()
        self.brand_detector = BrandDetector(self.config.get("brands", {}))
        self.campaign_correlator = CampaignCorrelator(self.config)
        self.campaign_builder = CampaignBuilder(self.config)

    def analyze(
        self,
        url: str,
        html: str | None = None,
        javascript: str | None = None,
        metadata: dict[str, Any] | None = None,
        export_misp: bool = True,
    ) -> dict[str, Any]:
        """
        Execute complete phishing analysis pipeline.

        Args:
            url: Target phishing URL.
            html: Pre-collected HTML (primary flow).
            javascript: Pre-collected JavaScript (optional).
            metadata: Partner-provided detection metadata.
            export_misp: Whether to export results to MISP.

        Returns:
            Complete analysis report dictionary.
        """
        logger.info("analysis_pipeline_start", url=url)
        self.audit_logger.log("analysis_start", {"url": url}, url)

        # Secondary flow: collect HTML if not provided
        if not html:
            logger.info("secondary_flow_html_collection", url=url)
            collection = self.html_collector.collect(url)
            html = collection.get("html", "")
            if not html:
                raise ValueError(f"Failed to collect HTML for {url}")

        # Preserve evidence (OPSEC)
        html_evidence = self.evidence_store.store("html", html, url)
        html_hash = html_evidence["sha256"]

        js_content = javascript or ""
        js_hash = ""
        if js_content:
            js_evidence = self.evidence_store.store("javascript", js_content, url)
            js_hash = js_evidence["sha256"]

        # Static analysis
        self.dom_analyzer.base_url = url
        dom = self.dom_analyzer.analyze(html, url)

        # Extract inline scripts for JS analysis
        inline_scripts = [s.content_preview for s in dom.scripts if s.inline and s.content_preview]
        if not js_content and inline_scripts:
            js_content = "\n".join(inline_scripts)

        javascript_finding = self.js_analyzer.analyze(js_content, inline_scripts)
        if not js_hash and javascript_finding.script_hash:
            js_hash = javascript_finding.script_hash

        phishing_type = self.form_classifier.classify(dom, dom.normalized_dom)
        exfiltration = self.exfil_analyzer.analyze(dom, javascript_finding)
        kit_fp = self.kit_fingerprinter.fingerprint(dom, javascript_finding)
        brand = self.brand_detector.detect(dom, dom.normalized_dom)

        # Infrastructure and SSL collection
        ssl_cert = self.ssl_collector.collect(url)
        infrastructure = self.infra_collector.collect(url)

        # IOC extraction
        iocs = self._extract_iocs(dom, javascript_finding, infrastructure)

        # Build analysis result
        result = AnalysisResult(
            url=url,
            html_hash=html_hash,
            javascript_hash=js_hash,
            dom=dom,
            javascript=javascript_finding,
            phishing_type=phishing_type,
            exfiltration=exfiltration,
            kit_fingerprint=kit_fp,
            brand=brand,
            ssl=ssl_cert,
            infrastructure=infrastructure,
            iocs=iocs,
            analyzed_at=utc_now(),
            metadata=metadata or {},
        )

        # Campaign correlation
        attribution = self.campaign_correlator.correlate(result)

        # Persist campaign
        campaign = self.campaign_builder.build_and_persist(result, attribution)

        # MISP export
        misp_event = None
        if export_misp:
            misp_event = self.campaign_builder.export_to_misp(result, attribution)

        # Audit trail
        report = {
            "url": url,
            "html_hash": html_hash,
            "javascript_hash": js_hash,
            "phishing_type": phishing_type.value,
            "brand": brand.brand if brand else None,
            "campaign_id": attribution.campaign_id,
            "attribution_score": attribution.score,
            "confidence": attribution.confidence.value,
            "kit_fingerprint": kit_fp.campaign_fingerprint,
            "exfiltration_destinations": len(exfiltration.destinations),
            "iocs": iocs.model_dump(),
            "misp_event": misp_event,
            "signals": [s.model_dump() for s in attribution.signals],
        }

        self.audit_logger.log("analysis_complete", report, url)

        logger.info(
            "analysis_pipeline_complete",
            url=url,
            campaign_id=attribution.campaign_id,
            score=attribution.score,
        )
        return report

    def analyze_multi_profile(self, url: str) -> dict[str, Any]:
        """
        Analyze URL across multiple render profiles and compute diffs.

        Args:
            url: Target URL.

        Returns:
            Multi-profile analysis with DOM/asset/script diffs.
        """
        logger.info("multi_profile_analysis_start", url=url)

        profiles = self.html_collector.collect_multi_profile(url)
        profile_diffs: list[ProfileDiff] = []
        profile_keys = list(RenderProfile)

        # Analyze each profile
        profile_analyses: dict[str, AnalysisResult] = {}
        for profile_name, collection in profiles.items():
            if "error" in collection:
                continue
            html = collection.get("html", "")
            if html:
                report = self.analyze(
                    url, html=html, export_misp=False
                )
                profile_analyses[profile_name] = report

        # Compute diffs between desktop and mobile profiles
        desktop_key = RenderProfile.DESKTOP_CHROME.value
        mobile_key = RenderProfile.ANDROID_CHROME.value

        if desktop_key in profiles and mobile_key in profiles:
            desktop_html = profiles[desktop_key].get("html", "")
            mobile_html = profiles[mobile_key].get("html", "")

            if desktop_html and mobile_html:
                desktop_dom = self.dom_analyzer.analyze(desktop_html, url)
                mobile_dom = self.dom_analyzer.analyze(mobile_html, url)

                diff = ProfileDiff(
                    profile_a=RenderProfile.DESKTOP_CHROME,
                    profile_b=RenderProfile.ANDROID_CHROME,
                    dom_diff=self._compute_diff(
                        desktop_dom.normalized_dom, mobile_dom.normalized_dom
                    ),
                    asset_diff=self._compute_diff(
                        [a.url for a in desktop_dom.assets],
                        [a.url for a in mobile_dom.assets],
                    ),
                    script_diff=self._compute_diff(
                        [s.src for s in desktop_dom.scripts],
                        [s.src for s in mobile_dom.scripts],
                    ),
                )
                profile_diffs.append(diff)

        return {
            "url": url,
            "profiles_collected": list(profiles.keys()),
            "profile_diffs": [d.model_dump() for d in profile_diffs],
        }

    def _extract_iocs(
        self,
        dom: Any,
        javascript: Any,
        infrastructure: Any,
    ) -> IOCFinding:
        """Extract IOCs from analysis components."""
        iocs = IOCFinding()

        # Domains and URLs from DOM
        for link in dom.links:
            if link.href.startswith("http"):
                iocs.urls.append(link.href)

        iocs.urls.extend(dom.external_urls)
        iocs.urls.extend(javascript.hardcoded_urls)

        # IPs from infrastructure
        if infrastructure and infrastructure.ip:
            iocs.ips.append(infrastructure.ip)

        # Email addresses
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        for comment in dom.html_comments:
            iocs.emails.extend(email_pattern.findall(comment))

        # Deduplicate
        iocs.domains = list({u.split("/")[2] if "://" in u else u for u in iocs.urls if u})
        iocs.urls = list(dict.fromkeys(iocs.urls))
        iocs.ips = list(dict.fromkeys(iocs.ips))
        iocs.emails = list(dict.fromkeys(iocs.emails))

        return iocs

    @staticmethod
    def _compute_diff(a: Any, b: Any) -> list[str]:
        """Compute set difference between two collections."""
        set_a = set(a) if isinstance(a, list) else set(str(a).split())
        set_b = set(b) if isinstance(b, list) else set(str(b).split())
        return sorted(set_a.symmetric_difference(set_b))


def main() -> None:
    """CLI entry point for phishing intelligence platform."""
    parser = argparse.ArgumentParser(
        description="Phishing Intelligence Platform - CTI Analysis Tool"
    )
    parser.add_argument("url", help="Target phishing URL")
    parser.add_argument("--html", help="Pre-collected HTML file path")
    parser.add_argument("--javascript", help="Pre-collected JavaScript file path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument(
        "--multi-profile", action="store_true", help="Run multi-profile analysis"
    )
    parser.add_argument("--no-misp", action="store_true", help="Skip MISP export")
    parser.add_argument(
        "--output", "-o", help="Output JSON file path", default=None
    )

    args = parser.parse_args()

    platform = PhishingIntelPlatform(config_path=args.config)

    html_content = None
    js_content = None

    if args.html:
        html_content = Path(args.html).read_text(encoding="utf-8")
    if args.javascript:
        js_content = Path(args.javascript).read_text(encoding="utf-8")

    if args.multi_profile:
        report = platform.analyze_multi_profile(args.url)
    else:
        report = platform.analyze(
            args.url,
            html=html_content,
            javascript=js_content,
            export_misp=not args.no_misp,
        )

    output = json.dumps(report, indent=2, default=str)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Report saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
