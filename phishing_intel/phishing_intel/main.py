"""Main orchestration pipeline for phishing campaign intelligence."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import yaml

from phishing_intel.analyzers.brand_detector import BrandDetector
from phishing_intel.analyzers.dom_analyzer import DomAnalyzer
from phishing_intel.analyzers.exfiltration_analyzer import ExfiltrationAnalyzer
from phishing_intel.analyzers.form_classifier import FormClassifier
from phishing_intel.analyzers.javascript_analyzer import JavaScriptAnalyzer
from phishing_intel.analyzers.kit_fingerprint import KitFingerprintAnalyzer
from phishing_intel.collectors.html_collector import HtmlCollectionResult, HtmlCollector
from phishing_intel.collectors.infrastructure_collector import InfrastructureCollector
from phishing_intel.collectors.ssl_collector import SslCollector
from phishing_intel.correlators.campaign_correlator import CampaignCorrelator
from phishing_intel.database.models import Base
from phishing_intel.database.repositories import (
    CampaignRepository,
    CertificateRepository,
    EvidenceRepository,
    FingerprintRepository,
    InfrastructureRepository,
    MispEventRepository,
    ProfileComparisonRepository,
    SiteRepository,
)
from phishing_intel.database.session import build_engine, build_session_factory
from phishing_intel.enrichment.campaign_builder import CampaignBuilder
from phishing_intel.enrichment.misp_client import MispClient
from phishing_intel.enrichment.taxonomy_mapper import TaxonomyMapper
from phishing_intel.models.findings import EvidenceRecord


class JsonLogFormatter(logging.Formatter):
    """Very small JSON formatter to support structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        """Format one log record as JSON."""

        payload = {
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
        }
        if hasattr(record, "extra_data"):
            payload["extra_data"] = getattr(record, "extra_data")
        return json.dumps(payload, ensure_ascii=True)


def configure_logger(level: str) -> logging.Logger:
    """Initialize structured logger for CTI pipeline operations."""

    logger = logging.getLogger("phishing_intel")
    logger.setLevel(level.upper())
    handler = logging.StreamHandler()
    handler.setFormatter(JsonLogFormatter())
    logger.handlers = [handler]
    return logger


@dataclass(slots=True)
class PipelineInput:
    """Input payload for one phishing analysis execution."""

    url: str
    html: str | None = None
    javascript: list[str] | None = None


class PhishingIntelPipeline:
    """Coordinates collection, analysis, correlation, persistence and enrichment."""

    def __init__(self, config_path: Path) -> None:
        self.config = self._load_config(config_path)
        self.logger = configure_logger(self.config["app"]["log_level"])

        db_url = self.config["database"]["url"]
        engine = build_engine(db_url)
        Base.metadata.create_all(bind=engine)
        self.session_factory = build_session_factory(db_url)

        self.html_collector = HtmlCollector(
            timeout=self.config["analysis"]["request_timeout"],
            user_agent=self.config["analysis"]["user_agent"],
        )
        self.dom_analyzer = DomAnalyzer()
        self.js_analyzer = JavaScriptAnalyzer()
        self.form_classifier = FormClassifier()
        self.exfiltration_analyzer = ExfiltrationAnalyzer()
        self.fingerprint_analyzer = KitFingerprintAnalyzer()
        self.brand_detector = BrandDetector()
        self.infrastructure_collector = InfrastructureCollector()
        self.ssl_collector = SslCollector()
        self.campaign_correlator = CampaignCorrelator(self.config["analysis"]["attribution_weights"])
        self.taxonomy_mapper = TaxonomyMapper()
        self.campaign_builder = CampaignBuilder()

    def run(self, payload: PipelineInput) -> dict[str, str | int | float | list[str]]:
        """Execute complete phishing intelligence workflow for one incident."""

        normalized_input = self._normalize_input(payload)
        domain = urlparse(normalized_input.url).netloc
        if not domain:
            raise ValueError(f"URL inválida para análise: {normalized_input.url}")

        dom_result = self.dom_analyzer.analyze(normalized_input.html, base_url=normalized_input.url)
        js_result = self.js_analyzer.analyze(normalized_input.javascript_blobs)
        phishing_type = self.form_classifier.classify(dom_result, normalized_input.html)
        exfiltration = self.exfiltration_analyzer.analyze(dom_result, js_result)
        fingerprint = self.fingerprint_analyzer.build(dom_result, js_result)
        brand = self.brand_detector.detect(dom_result, normalized_input.html)
        infrastructure = self.infrastructure_collector.collect(domain)
        ssl_metadata = self._safe_collect_ssl(domain)

        attribution = self.campaign_correlator.attribute(
            campaign_id=f"cmp-{fingerprint.campaign_fingerprint[:12]}",
            fingerprint_match=False,
            certificate_match=False,
            asn_match=False,
            provider_match=False,
            brand_match=False,
            historical_matches=[],
        )

        tags = self.taxonomy_mapper.build_tags(
            brand=brand.target_brand,
            phishing_type=phishing_type,
            campaign_id=attribution.campaign_id,
            confidence=attribution.confidence_level,
            exfiltration=exfiltration,
        )
        campaign_payload = self.campaign_builder.build_payload(
            attribution=attribution,
            fingerprint=fingerprint,
            ssl=ssl_metadata,
            brand=brand,
            phishing_type=phishing_type,
            infrastructure=infrastructure,
        )

        evidence = EvidenceRecord(
            url=normalized_input.url,
            html_hash=normalized_input.html_hash,
            javascript_hash=normalized_input.javascript_hash,
            ssl_fingerprint=ssl_metadata.sha256_fingerprint if ssl_metadata else None,
            analysis_summary={
                "campaign_id": attribution.campaign_id,
                "target_brand": brand.target_brand,
                "phishing_type": phishing_type.value,
                "exfiltration_score": exfiltration.score,
                "confidence": attribution.confidence_level,
            },
        )
        artifact_paths = self._store_artifacts(
            url=normalized_input.url,
            html=normalized_input.html,
            javascript=normalized_input.javascript_blobs,
            campaign_id=attribution.campaign_id,
        )
        self._persist(
            url=normalized_input.url,
            domain=domain,
            html_hash=normalized_input.html_hash,
            javascript_hash=normalized_input.javascript_hash,
            campaign_id=attribution.campaign_id,
            campaign_score=attribution.attribution_score,
            confidence=attribution.confidence_level,
            infrastructure=infrastructure,
            fingerprint_data=fingerprint.model_dump(),
            ssl_metadata=ssl_metadata.model_dump() if ssl_metadata else None,
            evidence=evidence,
            raw_html=normalized_input.html,
            raw_javascript=normalized_input.javascript_blobs,
            artifact_paths=artifact_paths,
        )
        self._send_to_misp_if_enabled(
            url=normalized_input.url,
            domain=domain,
            infrastructure_ip=infrastructure.ip,
            ssl_fingerprint=ssl_metadata.sha256_fingerprint if ssl_metadata else None,
            campaign_id=attribution.campaign_id,
            tags=tags,
            campaign_payload=campaign_payload,
        )

        summary = {
            "campaign_id": attribution.campaign_id,
            "campaign_score": attribution.attribution_score,
            "confidence_level": attribution.confidence_level,
            "target_brand": brand.target_brand,
            "phishing_type": phishing_type.value,
            "dom_hash": dom_result.dom_hash,
            "campaign_fingerprint": fingerprint.campaign_fingerprint,
            "exfiltration_types": [item.destination_type.value for item in exfiltration.destinations],
            "tags": tags,
            "artifact_paths": artifact_paths,
            "misp_payload_preview": campaign_payload,
        }
        self.logger.info("analysis_completed", extra={"extra_data": summary})
        return summary

    def compare_profiles(self, url: str, profile_html: dict[str, str], profile_javascript: dict[str, list[str]]) -> None:
        """Analyze desktop/mobile profiles and store DOM/script/asset diffs."""

        if len(profile_html) < 2:
            return
        session = self.session_factory()
        try:
            repository = ProfileComparisonRepository(session)
            baseline_name = sorted(profile_html.keys())[0]
            baseline_dom = self.dom_analyzer.analyze(profile_html[baseline_name], base_url=url)
            baseline_js = self.js_analyzer.analyze(profile_javascript.get(baseline_name, []))
            baseline_fp = self.fingerprint_analyzer.build(baseline_dom, baseline_js)

            for profile_name, html in profile_html.items():
                current_dom = self.dom_analyzer.analyze(html, base_url=url)
                current_js = self.js_analyzer.analyze(profile_javascript.get(profile_name, []))
                current_fp = self.fingerprint_analyzer.build(current_dom, current_js)
                dom_diff = {
                    "added_assets": sorted(set(current_dom.assets) - set(baseline_dom.assets)),
                    "removed_assets": sorted(set(baseline_dom.assets) - set(current_dom.assets)),
                    "added_scripts": sorted(set(current_dom.scripts) - set(baseline_dom.scripts)),
                    "removed_scripts": sorted(set(baseline_dom.scripts) - set(current_dom.scripts)),
                    "dom_hash_changed": [str(current_fp.dom_hash != baseline_fp.dom_hash)],
                }
                repository.store_comparison(
                    url=url,
                    profile_name=profile_name,
                    dom_hash=current_fp.dom_hash,
                    asset_hash=current_fp.asset_hash,
                    script_hash=current_fp.script_hash,
                    dom_diff=dom_diff,
                )
        finally:
            session.close()

    @staticmethod
    def _load_config(path: Path) -> dict:
        """Load YAML configuration file."""

        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def _normalize_input(self, payload: PipelineInput) -> HtmlCollectionResult:
        """Normalize incoming payload prioritizing provided HTML/JavaScript."""

        if payload.html:
            html_hash = hashlib.sha256(payload.html.encode("utf-8")).hexdigest()
            javascript = payload.javascript or []
            javascript_hash = (
                hashlib.sha256("\n".join(sorted(javascript)).encode("utf-8")).hexdigest() if javascript else None
            )
            return HtmlCollectionResult(
                url=payload.url,
                html=payload.html,
                javascript_blobs=javascript,
                html_hash=html_hash,
                javascript_hash=javascript_hash,
            )
        self.logger.info("fallback_html_collection", extra={"extra_data": {"url": payload.url}})
        return self.html_collector.collect(payload.url)

    def _safe_collect_ssl(self, domain: str):
        """Collect SSL metadata while avoiding pipeline interruption."""

        try:
            return self.ssl_collector.collect(domain)
        except Exception as exc:
            self.logger.error(
                "ssl_collection_failed",
                extra={"extra_data": {"domain": domain, "error": str(exc)}},
            )
            return None

    def _persist(
        self,
        url: str,
        domain: str,
        html_hash: str,
        javascript_hash: str | None,
        campaign_id: str,
        campaign_score: int,
        confidence: str,
        infrastructure,
        fingerprint_data: dict[str, str],
        ssl_metadata: dict | None,
        evidence: EvidenceRecord,
        raw_html: str,
        raw_javascript: list[str],
        artifact_paths: dict[str, str],
    ) -> None:
        """Persist campaign, evidence and infrastructure entities."""

        session = self.session_factory()
        try:
            campaign_repo = CampaignRepository(session)
            site_repo = SiteRepository(session)
            infra_repo = InfrastructureRepository(session)
            cert_repo = CertificateRepository(session)
            fp_repo = FingerprintRepository(session)
            evidence_repo = EvidenceRepository(session)

            campaign = campaign_repo.create_campaign(campaign_id=campaign_id, score=campaign_score, confidence=confidence)
            site_repo.create_site(
                url=url,
                domain=domain,
                html_hash=html_hash,
                javascript_hash=javascript_hash,
                campaign_db_id=campaign.id,
            )
            if infrastructure.ip:
                infra_repo.create_infrastructure(
                    domain=domain,
                    ip=infrastructure.ip,
                    asn=infrastructure.asn,
                    provider=infrastructure.provider,
                    organization=infrastructure.organization,
                    country=infrastructure.country,
                )
            if ssl_metadata:
                cert_repo.create_certificate(
                    serial_number=ssl_metadata["serial_number"],
                    issuer=ssl_metadata["issuer"],
                    fingerprint=ssl_metadata["sha256_fingerprint"],
                    subject=ssl_metadata["subject"],
                    san=ssl_metadata["san"],
                    not_before=ssl_metadata["not_before"],
                    not_after=ssl_metadata["not_after"],
                    pem=ssl_metadata["pem"],
                )
            fp_repo.create_fingerprint(
                dom_hash=fingerprint_data["dom_hash"],
                asset_hash=fingerprint_data["asset_hash"],
                script_hash=fingerprint_data["script_hash"],
                campaign_fingerprint=fingerprint_data["campaign_fingerprint"],
            )
            evidence_repo.store_audit(
                timestamp=evidence.timestamp,
                url=url,
                html_hash=html_hash,
                javascript_hash=javascript_hash,
                ssl_fingerprint=evidence.ssl_fingerprint,
                raw_html=raw_html,
                raw_javascript=raw_javascript,
                analysis_result={**evidence.analysis_summary, **artifact_paths},
            )
        finally:
            session.close()

    def _store_artifacts(self, url: str, html: str, javascript: list[str], campaign_id: str) -> dict[str, str]:
        """Persist raw evidence artifacts for chain-of-custody requirements."""

        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d%H%M%S")
        base = Path("artifacts") / campaign_id
        base.mkdir(parents=True, exist_ok=True)
        html_path = base / f"{timestamp}_page.html"
        js_path = base / f"{timestamp}_scripts.json"
        metadata_path = base / f"{timestamp}_metadata.json"

        html_path.write_text(html, encoding="utf-8")
        js_path.write_text(json.dumps(javascript, ensure_ascii=False, indent=2), encoding="utf-8")
        metadata_path.write_text(
            json.dumps(
                {
                    "timestamp": timestamp,
                    "url": url,
                    "html_sha256": hashlib.sha256(html.encode("utf-8")).hexdigest(),
                    "javascript_sha256": hashlib.sha256("\n".join(javascript).encode("utf-8")).hexdigest()
                    if javascript
                    else None,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return {
            "html_artifact": str(html_path),
            "javascript_artifact": str(js_path),
            "metadata_artifact": str(metadata_path),
        }

    def _send_to_misp_if_enabled(
        self,
        url: str,
        domain: str,
        infrastructure_ip: str | None,
        ssl_fingerprint: str | None,
        campaign_id: str,
        tags: list[str],
        campaign_payload: dict[str, str],
    ) -> None:
        """Push incident context to MISP and persist event mapping."""

        if not self.config["misp"].get("enabled", False):
            return
        session = self.session_factory()
        try:
            client = MispClient(
                url=self.config["misp"]["url"],
                api_key=self.config["misp"]["api_key"],
                verify_tls=self.config["misp"]["verify_tls"],
            )
            event_info = f"Phishing campaign {campaign_id}"
            event_ids = client.create_event(info=event_info)
            client.add_attribute(event_ids["event_id"], "domain", domain, "Network activity")
            client.add_attribute(event_ids["event_id"], "url", url, "Network activity")
            if infrastructure_ip:
                client.add_attribute(event_ids["event_id"], "ip-dst", infrastructure_ip, "Network activity")
            if ssl_fingerprint:
                client.add_attribute(event_ids["event_id"], "x509-fingerprint-sha256", ssl_fingerprint, "Artifacts dropped")
            client.add_phishing_campaign_object(event_ids["event_id"], campaign_payload)
            client.tag_event(event_ids["event_id"], tags)

            misp_repo = MispEventRepository(session)
            misp_repo.create_event_mapping(
                event_uuid=event_ids["event_uuid"],
                event_id=event_ids["event_id"],
                campaign_id=campaign_id,
            )
            self.logger.info("misp_event_enriched", extra={"extra_data": event_ids})
        except Exception as exc:
            self.logger.error("misp_enrichment_failed", extra={"extra_data": {"error": str(exc)}})
        finally:
            session.close()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments used by the standalone pipeline runner."""

    parser = argparse.ArgumentParser(description="Phishing intelligence pipeline")
    parser.add_argument("--url", required=True, help="Suspicious URL under analysis")
    parser.add_argument("--html-file", help="Optional path to pre-collected HTML file")
    parser.add_argument("--js-file", action="append", default=[], help="Optional JS file path. Can be repeated.")
    parser.add_argument(
        "--config-file",
        default=str(Path(__file__).resolve().parent / "config" / "config.yaml"),
        help="Path to YAML config file",
    )
    parser.add_argument(
        "--profiles-file",
        help="Optional JSON file with profile HTML/JS for multi-profile diff storage.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint for CTI automation pipeline."""

    args = parse_args()
    html = Path(args.html_file).read_text(encoding="utf-8") if args.html_file else None
    javascript = [Path(path).read_text(encoding="utf-8") for path in args.js_file] if args.js_file else []

    pipeline = PhishingIntelPipeline(config_path=Path(args.config_file))
    result = pipeline.run(PipelineInput(url=args.url, html=html, javascript=javascript))
    if args.profiles_file:
        profiles_payload = json.loads(Path(args.profiles_file).read_text(encoding="utf-8"))
        pipeline.compare_profiles(
            url=args.url,
            profile_html=profiles_payload.get("html", {}),
            profile_javascript=profiles_payload.get("javascript", {}),
        )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
