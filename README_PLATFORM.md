# Threat Hunting Collection Platform

A modular, production-oriented **Cyber Threat Intelligence (CTI) collection
platform** for Threat Hunting, OSINT, Brand & VIP monitoring, Dark/Deep Web
monitoring, credential/IOC/card/leak/document hunting, campaign & threat-actor
discovery, correlation, scoring, enrichment, export and audit.

It is built as a **platform**, not a bag of scripts: Clean Architecture,
Hexagonal (Ports & Adapters), Domain Driven Design, SOLID, an event-driven
collection pipeline and a plugin-based connector SDK. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design rationale
(read it first — it is the source of truth).

> This platform is the modern successor to the original `CrawlerDark` project in
> this repository. The legacy dark-web scraper (`main.py`, `frameworks/`) still
> works standalone; the new platform lives under `threat_hunting/`.

---

## Highlights

- **Uniform `Finding` model** — every connector, from Reddit to a Tor leak site,
  produces the *same* canonical model. Downstream stages are source-agnostic.
- **Connector SDK + auto-discovery** — add a source by subclassing
  `BaseConnector` and dropping a module in `sources/` (or shipping a plugin via
  the `threat_hunting.connectors` entry-point group). No core edits.
- **Mandatory decoupled pipeline** — Connector → Parser → Extractor →
  Normalizer → Detection → Scoring → Correlation → Deduplication → Enrichment →
  Persistence → Export.
- **Configurable engines** — detection rules (regex/keyword/IOC/threat-actor/
  heuristic/YARA), a fully-weighted scoring model, correlation into campaigns,
  multi-strategy deduplication and pluggable enrichment. Nothing hardcoded.
- **OPSEC transport layer** — proxies (HTTP/HTTPS/SOCKS5/Tor), User-Agent
  rotation, rate limiting, retries/backoff and env-based secrets, per-connector
  profiles. Connectors never touch the network directly.
- **Swappable storage** — memory / JSON / SQLite out of the box behind
  Repository + Unit of Work (Postgres/OpenSearch/Splunk/Parquet/S3 plug in the
  same way).
- **Exporters** — JSON, CSV, STIX 2.1, Webhook/REST, MISP; automatic MISP export
  when a finding's score crosses a configurable threshold (event-driven).
- **Observability** — structured `structlog` logging, Prometheus metrics,
  OpenTelemetry tracing hooks and aggregated health checks. All degrade
  gracefully when the optional backend is absent.

## Install

```bash
# with Poetry (recommended)
poetry install                 # core
poetry install -E full         # + SQLAlchemy, Redis, APScheduler, PyMISP, OTel, DI

# or plain pip (core deps)
pip install pydantic structlog typer httpx beautifulsoup4 lxml pyyaml prometheus-client
```

The **core runs with zero optional dependencies**: SQLAlchemy, Redis,
APScheduler, PyMISP, OpenTelemetry, `dependency-injector` and `yara-python` are
all optional and the code degrades gracefully without them.

## Quickstart (CLI)

```bash
# List auto-discovered connectors
hunt connector list

# Run the self-contained sample connector through the whole pipeline
hunt run sample_paste

# Run by group ("leak", "social", "darkweb", ...) or everything
hunt run leak
hunt run all

# Score the sample corpus and show the explainable score breakdown
hunt score test

# Enable/disable a connector, run the scheduler, export, check health
hunt connector disable reddit
hunt scheduler run --targets sample_paste --once
hunt export json
hunt health
```

`--config/-c` points at a settings file (defaults to `config/settings.yml`).
Environment overrides: `TH_STORAGE_BACKEND`, `TH_SCORE_THRESHOLD`,
`TH_OPSEC_OFFLINE`, `TH_LOG_LEVEL`, `TH_CONFIG`.

> **OPSEC note:** `opsec.offline: true` (the default) disables all network
> egress, which is the safe default for CI/sandboxes. Set it to `false` and
> configure profiles/proxies in `config/settings.yml` to collect from live
> sources. The `darkweb` connector is pre-wired to the `tor` SOCKS5 profile.

## Adding a connector

```python
from collections.abc import Iterable
from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class MySourceConnector(BaseConnector):
    meta = ConnectorMeta(
        name="mysource",
        source=SourceType.WEBSITE,
        category=Category.OSINT,
        groups=["osint"],
    )

    def collect(self) -> Iterable[RawItem]:
        resp = self.transport.get("https://example.com/feed")  # OPSEC-managed
        if resp.ok:
            yield RawItem(connector=self.meta.name, source="example", content=resp.text)
```

Drop this in `threat_hunting/infrastructure/connectors/sources/` and it is
discovered automatically — `hunt run mysource` just works.

## Configuration

- `config/settings.yml` — storage, export threshold, OPSEC profiles, detection
  regex/YARA rules, whitelist/blacklist, scoring weights, enabled connectors.
- `config/watchlists.yml` — brands, VIPs, domains, keywords and threat actors
  consumed by the detection engine. Everything is data — no code change to add a
  monitored term.

## Testing

```bash
pytest                                   # 115 tests
pytest --cov=threat_hunting --cov-report=term-missing   # ~93% coverage
```

## Django-readiness

Every piece of management data (connectors, keywords, VIPs, actors, watchlists,
rules, scheduler, proxies, integrations, findings, exports, logs, metrics, jobs)
sits behind ports and Pydantic models. A future Django admin becomes *another
adapter* over the same application services — no core changes required.
