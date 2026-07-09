"""Integration tests for full phishing intelligence pipeline."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine, text

from phishing_intel.main import PhishingIntelPipeline, PipelineInput
from phishing_intel.models.infrastructure import DnsRecordSet, InfrastructureProfile


def test_pipeline_end_to_end_with_supplied_html_js(tmp_path: Path, sample_html: str, sample_javascript: list[str]) -> None:
    db_path = tmp_path / "intel.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
app:
  name: phishing-intel
  log_level: INFO
database:
  url: sqlite:///{db_path}
misp:
  enabled: false
  url: https://misp.local
  api_key: test
  verify_tls: false
analysis:
  request_timeout: 5
  user_agent: test-agent
  attribution_weights:
    fingerprint: 35
    certificate: 25
    asn: 15
    provider: 10
    brand: 15
""",
        encoding="utf-8",
    )
    pipeline = PhishingIntelPipeline(config_path=config_path)
    pipeline.infrastructure_collector.collect = lambda domain: InfrastructureProfile(
        domain=domain,
        ip="1.2.3.4",
        asn="AS123",
        organization="Test Org",
        provider="Test Provider",
        country="BR",
        dns=DnsRecordSet(a_records=["1.2.3.4"], mx_records=[], ns_records=[]),
    )
    pipeline.ssl_collector.collect = lambda domain: (_ for _ in ()).throw(RuntimeError("skip ssl"))

    result = pipeline.run(PipelineInput(url="https://phish.example/login", html=sample_html, javascript=sample_javascript))
    assert result["campaign_id"].startswith("cmp-")
    assert result["target_brand"] == "itau"
    assert result["phishing_type"] == "card_harvesting"
    assert result["artifact_paths"]


def test_profile_comparison_persistence(tmp_path: Path) -> None:
    db_path = tmp_path / "intel.db"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        f"""
app:
  name: phishing-intel
  log_level: INFO
database:
  url: sqlite:///{db_path}
misp:
  enabled: false
  url: https://misp.local
  api_key: test
  verify_tls: false
analysis:
  request_timeout: 5
  user_agent: test-agent
  attribution_weights:
    fingerprint: 35
    certificate: 25
    asn: 15
    provider: 10
    brand: 15
""",
        encoding="utf-8",
    )
    pipeline = PhishingIntelPipeline(config_path=config_path)
    profiles = {
        "desktop_chrome": "<html><body><script src='/a.js'></script></body></html>",
        "android_chrome": "<html><body><script src='/b.js'></script><img src='/x.png'></body></html>",
    }
    js = {"desktop_chrome": ["fetch('/a')"], "android_chrome": ["fetch('/b')"]}
    pipeline.compare_profiles("https://phish.example", profiles, js)

    engine = create_engine(f"sqlite:///{db_path}")
    with engine.connect() as connection:
        count = connection.execute(text("SELECT COUNT(*) FROM profile_comparisons")).scalar_one()
    assert count == 2
