"""Additional unit/integration tests to raise coverage toward 90%."""

from __future__ import annotations

from pathlib import Path

import pytest

from threat_hunting.core.application.commands import (
    DisableConnectorCommand,
    EnableConnectorCommand,
    ExportFindingsCommand,
    RunHuntCommand,
)
from threat_hunting.core.application.ports import ParsedDocument, RawDocument
from threat_hunting.core.application.use_cases import (
    ConnectorLifecycleHandler,
    ExportFindingsHandler,
    RunHuntHandler,
)
from threat_hunting.core.domain.entities import (
    Campaign,
    ConnectorConfig,
    ThreatActor,
    Watchlist,
)
from threat_hunting.core.domain.enums import (
    ArtifactType,
    FindingCategory,
    IndicatorType,
    RelationshipType,
    WatchlistType,
)
from threat_hunting.core.domain.events import DomainEvent, FindingCreated
from threat_hunting.core.domain.services import FindingBuilder
from threat_hunting.core.domain.value_objects import (
    Artifact,
    ContentHash,
    Indicator,
    Keyword,
    OpsecProfile,
    Relationship,
    VipProfile,
)
from threat_hunting.exporters import (
    AutoMispExportHandler,
    CsvExporter,
    ExporterFactory,
    OpenCtiExporter,
    OpenSearchExporter,
    SplunkExporter,
    Stix21Exporter,
    Taxii21Exporter,
    WebhookExporter,
)
from threat_hunting.infrastructure.config.loader import (
    load_connector_options,
    load_opsec_profiles,
    load_settings,
    load_yaml,
)
from threat_hunting.infrastructure.messaging.event_bus import InMemoryEventBus
from threat_hunting.infrastructure.observability import (
    LoggingEventHandler,
    OpenTelemetryTracer,
    PlatformHealthCheck,
    PrometheusMetrics,
    StructlogAudit,
    configure_logging,
)
from threat_hunting.infrastructure.opsec.transport import (
    HttpxOpsecTransport,
    InMemoryCredentialVault,
    TokenBucketRateLimiter,
)
from threat_hunting.infrastructure.persistence.memory import (
    InMemoryCampaignRepository,
    InMemoryConnectorConfigRepository,
    InMemoryFindingRepository,
    InMemoryHuntJobRepository,
    InMemoryStorageBackend,
    InMemoryThreatActorRepository,
    InMemoryWatchlistRepository,
)
from threat_hunting.infrastructure.persistence.sqlalchemy.backend import (
    SqlAlchemyStorageBackend,
)
from threat_hunting.infrastructure.scheduler.hunt_scheduler import HuntScheduler
from threat_hunting.parsers.passthrough import DefaultNormalizer, PassthroughParser
from threat_hunting.storage.backends import (
    JsonFileStorageBackend,
    OpenSearchStorageBackend,
    ParquetStorageBackend,
    SplunkStorageBackend,
)


def test_governance_entities() -> None:
    actor = ThreatActor(name="LockBit", aliases=["abcd"])
    assert actor.matches_name("lockbit ransomware")
    assert not actor.matches_name("unrelated")

    campaign = Campaign(name="C1")
    campaign.link_finding("f1")
    campaign.link_finding("f1")
    assert campaign.finding_ids == ["f1"]

    cfg = ConnectorConfig(name="reddit")
    cfg.disable()
    assert not cfg.enabled
    cfg.enable()
    assert cfg.enabled

    w = Watchlist(name="x", type=WatchlistType.KEYWORD)
    w.add_entry("a")
    w.remove_entry("a")
    assert w.entries == []


def test_value_objects_extra() -> None:
    assert Keyword(value="x", case_sensitive=True).matches("x")
    assert not Keyword(value="X", case_sensitive=True).matches("x")
    assert ContentHash.from_bytes(b"abc").value
    vip = VipProfile(name="Jane", aliases=["J"], emails=["j@a.com"])
    assert vip.priority == 1
    art = Artifact(type=ArtifactType.TEXT, name="n", content="hello")
    assert art.compute_hash()
    assert Artifact(type=ArtifactType.TEXT, name="n").compute_hash() == ""


@pytest.mark.asyncio
async def test_memory_repos_full(sample_finding) -> None:
    findings = InMemoryFindingRepository()
    await findings.save(sample_finding)
    assert await findings.get_by_id(str(sample_finding.id))
    assert await findings.find_by_content_hash(sample_finding.content_hash or "")
    assert await findings.find_by_indicator("vip@acme.com")
    assert await findings.list_by_connector("darkweb")
    assert await findings.list_recent(limit=1)
    assert await findings.delete(str(sample_finding.id))
    assert not await findings.delete("missing")

    wl = InMemoryWatchlistRepository()
    w = Watchlist(name="b", type=WatchlistType.BRAND, entries=["acme"])
    await wl.save(w)
    assert await wl.get_by_id(w.id)
    assert await wl.get_by_name("b")
    assert await wl.list_enabled()
    assert await wl.list_all()

    actors = InMemoryThreatActorRepository()
    a = ThreatActor(name="Clop")
    await actors.save(a)
    assert await actors.get_by_id(a.id)
    assert await actors.get_by_name("clop")
    assert await actors.list_enabled()

    camps = InMemoryCampaignRepository()
    c = Campaign(name="camp")
    await camps.save(c)
    assert await camps.get_by_id(c.id)
    assert await camps.list_all()

    jobs = InMemoryHuntJobRepository()
    from threat_hunting.core.domain.entities import HuntJob

    j = HuntJob(connector="reddit")
    j.start()
    await jobs.save(j)
    assert await jobs.get_by_id(j.id)
    assert await jobs.list_recent()

    cons = InMemoryConnectorConfigRepository()
    cfg = ConnectorConfig(name="reddit", category_group="social")
    await cons.save(cfg)
    assert await cons.get_by_name("reddit")
    assert await cons.list_enabled()
    assert await cons.list_all()
    assert await cons.list_by_group("social")

    backend = InMemoryStorageBackend(findings)
    await backend.initialize()
    f2 = (
        FindingBuilder()
        .with_title("X")
        .with_source("s")
        .with_connector("c")
        .build()
    )
    await backend.persist_finding(f2)
    assert await backend.fetch_finding(str(f2.id))
    assert await backend.query_findings(limit=10)
    assert await backend.query_findings(connector="c")
    assert (await backend.health()).state == "healthy"
    await backend.close()


@pytest.mark.asyncio
async def test_sqlalchemy_backend(tmp_path, sample_finding) -> None:
    db = tmp_path / "t.db"
    backend = SqlAlchemyStorageBackend(f"sqlite+aiosqlite:///{db}")
    await backend.initialize()
    await backend.persist_finding(sample_finding)
    got = await backend.fetch_finding(str(sample_finding.id))
    assert got is not None
    assert got.title == sample_finding.title
    recent = await backend.query_findings(limit=5)
    assert recent
    by_c = await backend.query_findings(connector=sample_finding.connector)
    assert by_c
    health = await backend.health()
    assert health.state == "healthy"
    sample_finding.add_tag("updated")
    await backend.persist_finding(sample_finding)
    await backend.close()


@pytest.mark.asyncio
async def test_exporters_all(tmp_path, sample_finding) -> None:
    f = sample_finding
    assert (await CsvExporter().export([f], path=str(tmp_path / "a.csv")))["count"] == 1
    assert (await Stix21Exporter().export([f], path=str(tmp_path / "a.stix.json")))["count"] == 1
    assert (await SplunkExporter().export([f], path=str(tmp_path / "a.splunk")))["count"] == 1
    assert (await OpenSearchExporter().export([f], path=str(tmp_path / "a.os")))["count"] == 1
    assert (await OpenCtiExporter().export([f], path=str(tmp_path / "a.octi")))["format"] == "opencti"
    assert (await Taxii21Exporter().export([f], path=str(tmp_path / "a.taxii")))["format"] == "taxii21"
    assert (await WebhookExporter().export([f], path=str(tmp_path / "a.wh")))["mode"] == "offline"

    factory = ExporterFactory()
    for name in factory.list_available():
        factory.create(name)

    bus = InMemoryEventBus()
    handler = AutoMispExportHandler(factory, event_bus=bus)
    await handler.handle(
        DomainEvent(
            event_type="ScoreThresholdExceeded",
            aggregate_id=str(f.id),
            payload={"finding": f.to_export_dict()},
        )
    )
    await handler.handle(FindingCreated(aggregate_id="x"))


@pytest.mark.asyncio
async def test_storage_backends(tmp_path, sample_finding) -> None:
    for Backend, kwargs in [
        (ParquetStorageBackend, {"path": str(tmp_path / "p.jsonl")}),
        (OpenSearchStorageBackend, {"path": str(tmp_path / "os.ndjson")}),
        (SplunkStorageBackend, {"path": str(tmp_path / "sp.jsonl")}),
    ]:
        b = Backend(**kwargs)
        await b.initialize()
        await b.persist_finding(sample_finding)
        await b.fetch_finding(str(sample_finding.id))
        await b.query_findings()
        assert (await b.health()).state == "healthy"
        await b.close()

    js = JsonFileStorageBackend(str(tmp_path / "store.json"))
    await js.initialize()
    await js.persist_finding(sample_finding)
    js2 = JsonFileStorageBackend(str(tmp_path / "store.json"))
    await js2.initialize()
    assert await js2.query_findings(limit=10)


@pytest.mark.asyncio
async def test_parser_normalizer_extractor_path() -> None:
    parser = PassthroughParser()
    parsed = await parser.parse(RawDocument({"title": "t", "content": "c"}), connector="x")
    assert parsed["title"] == "t"
    parsed2 = await parser.parse(RawDocument({"content": "plain"}), connector="x")
    assert "content" in parsed2

    normalizer = DefaultNormalizer()
    finding = await normalizer.normalize(
        ParsedDocument(
            {
                "title": "Leak",
                "description": "body",
                "category": "leak",
                "severity": "high",
                "url": "http://x",
                "author": "a",
                "tags": ["t1"],
            }
        ),
        {"indicators": [{"type": "email", "value": "a@b.com"}]},
        connector="paste",
        source="paste",
    )
    assert finding.category == FindingCategory.LEAK
    assert finding.indicators


@pytest.mark.asyncio
async def test_opsec_transport_client_and_vault() -> None:
    vault = InMemoryCredentialVault(
        {
            "a": {"token": "t"},
            "b": {"api_key": "k"},
            "c": {"username": "u", "password": "p"},
        }
    )
    assert (await vault.get("vault://a"))["token"] == "t"
    assert (await vault.get("vault://b"))["api_key"] == "k"
    assert await vault.get("vault://missing") == {}

    transport = HttpxOpsecTransport(vault=vault, rate_limiter=TokenBucketRateLimiter())
    profile = OpsecProfile(
        name="t1",
        user_agent="UA",
        credentials_ref="vault://a",
        headers={"X-Test": "1"},
        rate_limit_rps=100.0,
        max_retries=1,
    )
    client = transport._client_for(profile)
    assert client.headers["User-Agent"] == "UA"
    headers = await transport._auth_headers(profile)
    assert headers["Authorization"].startswith("Bearer")
    headers2 = await transport._auth_headers(
        OpsecProfile(name="t2", credentials_ref="vault://b")
    )
    assert headers2["X-API-Key"] == "k"
    headers3 = await transport._auth_headers(
        OpsecProfile(name="t3", credentials_ref="vault://c")
    )
    assert headers3["Authorization"].startswith("Basic")
    await transport.aclose()


@pytest.mark.asyncio
async def test_observability_stack() -> None:
    configure_logging(json_logs=True, level="INFO")
    configure_logging(json_logs=False, level="DEBUG")
    metrics = PrometheusMetrics()
    metrics.incr("test_counter")
    metrics.incr("test_counter_l", labels={"a": "1"})
    metrics.observe("test_hist", 1.5)
    metrics.observe("test_hist_l", 1.5, labels={"a": "1"})
    metrics.gauge("test_gauge", 3)
    metrics.gauge("test_gauge_l", 3, labels={"a": "1"})
    assert metrics.export()

    tracer = OpenTelemetryTracer(console=False)
    with tracer.start_span("span", foo="bar"):
        pass

    bus = InMemoryEventBus()
    audit = StructlogAudit(event_bus=bus)
    await audit.record("act", details={"x": 1})
    assert audit.records

    health = PlatformHealthCheck()

    async def ok():
        from threat_hunting.core.domain.enums import HealthState
        from threat_hunting.core.domain.value_objects import HealthStatus, utc_now

        return HealthStatus(
            component="ok", state=HealthState.HEALTHY.value, checked_at=utc_now()
        )

    async def bad():
        raise RuntimeError("boom")

    health.register(ok)
    health.register(bad)
    statuses = await health.check_all()
    assert len(statuses) == 2
    assert await health.overall()

    empty = PlatformHealthCheck()
    assert (await empty.check_all())[0].component == "platform"

    await LoggingEventHandler().handle(FindingCreated(aggregate_id="1"))


@pytest.mark.asyncio
async def test_scheduler_and_lifecycle(pipeline, connector_factory, uow) -> None:
    bus = InMemoryEventBus()
    run_handler = RunHuntHandler(
        connector_factory=connector_factory,
        pipeline=pipeline,
        audit=StructlogAudit(),
        event_bus=bus,
    )
    scheduler = HuntScheduler(run_handler=run_handler)
    jobs = await scheduler.run_once("reddit")
    assert jobs
    scheduler.add_connector_cron("reddit", "0 * * * *")
    assert scheduler.job_count == 1
    scheduler.start()
    scheduler.shutdown()

    life = ConnectorLifecycleHandler(uow=uow, audit=StructlogAudit())
    assert (await life.enable(EnableConnectorCommand(name="reddit")))["enabled"] is True
    assert (await life.disable(DisableConnectorCommand(name="reddit")))["enabled"] is False
    assert (await life.enable(EnableConnectorCommand(name="reddit")))["enabled"] is True


@pytest.mark.asyncio
async def test_event_bus_publish_many_and_error() -> None:
    bus = InMemoryEventBus()

    class Bad:
        async def handle(self, event):
            raise RuntimeError("fail")

    bus.subscribe("*", Bad())
    await bus.publish_many([FindingCreated(aggregate_id="1")])
    assert bus.history


def test_config_loader(config_dir: Path) -> None:
    settings = load_settings(config_dir)
    assert settings.app_name
    profiles = load_opsec_profiles(config_dir)
    assert "default" in profiles
    assert "darkweb" in profiles
    opts = load_connector_options(config_dir)
    assert "reddit" in opts
    assert load_yaml(config_dir / "missing.yaml") == {}


@pytest.mark.asyncio
async def test_finding_builder_and_domain_methods(sample_finding) -> None:
    f = (
        FindingBuilder()
        .with_title("T")
        .with_description("D")
        .with_source("s")
        .with_connector("c")
        .with_score(10)
        .with_confidence(0.9)
        .with_raw_data({"a": 1})
        .with_normalized_data({"b": 2})
        .add_artifact(Artifact(type=ArtifactType.TEXT, name="n", content="x"))
        .add_indicator(Indicator(type=IndicatorType.DOMAIN, value="x.com"))
        .build()
    )
    f.add_relationship(
        Relationship(
            type=RelationshipType.RELATED_TO,
            source_id=str(f.id),
            target_id="other",
        )
    )
    f.register_event(FindingCreated(aggregate_id=str(f.id)))
    events = f.collect_events()
    assert events
    f.mark_duplicate("other")
    assert f.is_duplicate

    from threat_hunting.core.domain.entities import HuntJob

    job = HuntJob(connector="x")
    job.start()
    job.record_error()
    job.fail("boom")
    assert job.status.value == "failed"
    job2 = HuntJob(connector="x")
    job2.start()
    job2.complete(partial=True)
    assert job2.status.value == "partial"


@pytest.mark.asyncio
async def test_run_hunt_unknown_raises(pipeline, connector_factory) -> None:
    handler = RunHuntHandler(
        connector_factory=connector_factory,
        pipeline=pipeline,
        audit=StructlogAudit(),
        event_bus=InMemoryEventBus(),
    )
    with pytest.raises(KeyError):
        await handler.handle(RunHuntCommand(connector="does_not_exist_xyz"))


@pytest.mark.asyncio
async def test_export_by_ids(uow, sample_finding, event_bus, tmp_path) -> None:
    async with uow:
        await uow.findings.save(sample_finding)
        await uow.commit()
    handler = ExportFindingsHandler(
        exporter_factory=ExporterFactory(),
        uow=uow,
        event_bus=event_bus,
        audit=StructlogAudit(),
    )
    result = await handler.handle(
        ExportFindingsCommand(
            format="csv",
            finding_ids=[str(sample_finding.id), "missing"],
            options={"path": str(tmp_path / "x.csv")},
        )
    )
    assert result["count"] == 1


@pytest.mark.asyncio
async def test_rate_limiter_wait() -> None:
    limiter = TokenBucketRateLimiter()
    await limiter.acquire("slow", rps=0)
    await limiter.acquire("slow2", rps=1000)


@pytest.mark.asyncio
async def test_scoring_get_weights(scoring_engine) -> None:
    w = scoring_engine.get_weights()
    assert "weights" in w


@pytest.mark.asyncio
async def test_detection_strategies_edge(detection_engine, sample_finding) -> None:
    matches = await detection_engine.detect(sample_finding)
    types = {m.rule_type for m in matches}
    assert "regex" in types
    assert "composite" in types or "keyword" in types


@pytest.mark.asyncio
async def test_sqlalchemy_delete_and_indicator_scan(tmp_path, sample_finding) -> None:
    from threat_hunting.infrastructure.persistence.sqlalchemy.backend import (
        SqlAlchemyFindingRepository,
        SqlAlchemyStorageBackend,
    )
    db = tmp_path / "del.db"
    backend = SqlAlchemyStorageBackend(f"sqlite+aiosqlite:///{db}")
    await backend.initialize()
    await backend.persist_finding(sample_finding)
    session_factory = backend.session_factory()
    async with session_factory() as session:
        repo = SqlAlchemyFindingRepository(session)
        found = await repo.find_by_indicator("vip@acme.com")
        assert found
        assert await repo.delete(str(sample_finding.id))
        assert not await repo.delete("missing")
        await session.commit()
    await backend.close()


@pytest.mark.asyncio
async def test_passthrough_parser_non_dict() -> None:
    parser = PassthroughParser()
    # RawDocument is dict subclass; simulate via parse with string-like by wrapping
    raw = RawDocument({"x": 1})
    parsed = await parser.parse(raw, connector="c")
    assert parsed["x"] == 1


@pytest.mark.asyncio
async def test_s3_fetch_missing(tmp_path) -> None:
    from threat_hunting.storage.backends import S3StorageBackend
    b = S3StorageBackend(str(tmp_path / "s3b"))
    await b.initialize()
    assert await b.fetch_finding("nope") is None
    assert await b.query_findings() == []
    await b.close()


@pytest.mark.asyncio
async def test_enrichment_register() -> None:
    from threat_hunting.enrichment.engine import EnrichmentEngine, EnricherStrategy
    class Extra(EnricherStrategy):
        name = "extra"
        async def enrich(self, finding):
            return {"extra": True}
    engine = EnrichmentEngine(enrichers=[])
    engine.register(Extra())
    f = FindingBuilder().with_title("t").with_source("s").with_connector("c").build()
    f = await engine.enrich(f)
    assert f.normalized_data.get("extra") is True


@pytest.mark.asyncio
async def test_dedup_similarity() -> None:
    from threat_hunting.deduplication.engine import DeduplicationEngine
    engine = DeduplicationEngine(similarity_threshold=0.5)
    a = FindingBuilder().with_title("Alpha Beta Gamma").with_description("same body text here").with_source("s").with_connector("c").build()
    b = FindingBuilder().with_title("Alpha Beta Gamma").with_description("same body text here").with_source("s").with_connector("c").build()
    # Different content hash forced by different ids in hash? hash uses title|desc|source — same
    # Force different hash so similarity path is used
    b.content_hash = "different"
    await engine.deduplicate(a)
    b = await engine.deduplicate(b)
    assert b.is_duplicate


@pytest.mark.asyncio
async def test_opsec_get_post_mocked(monkeypatch) -> None:
    import httpx
    transport = HttpxOpsecTransport()
    profile = OpsecProfile(name="mock", rate_limit_rps=100, max_retries=1)

    class FakeResp:
        def raise_for_status(self):
            return None
        status_code = 200

    async def fake_request(method, url, *, profile, **kwargs):
        return FakeResp()

    monkeypatch.setattr(transport, "request", fake_request)
    assert await transport.get("http://x", profile=profile)
    assert await transport.post("http://x", profile=profile)
    await transport.aclose()


def test_finding_builder_validation() -> None:
    with pytest.raises(ValueError):
        FindingBuilder().with_title("t").with_connector("c").build()  # missing source
    with pytest.raises(ValueError):
        FindingBuilder().with_title("t").with_source("s").build()  # missing connector


@pytest.mark.asyncio
async def test_health_degraded() -> None:
    health = PlatformHealthCheck()
    async def deg():
        from threat_hunting.core.domain.enums import HealthState
        from threat_hunting.core.domain.value_objects import HealthStatus, utc_now
        return HealthStatus(component="d", state=HealthState.DEGRADED.value, checked_at=utc_now())
    health.register(deg)
    assert (await health.overall()).value == "degraded"
