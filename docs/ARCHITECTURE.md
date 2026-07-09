# Threat Hunting Collection Platform — Architecture

> A modular, production-oriented Cyber Threat Intelligence (CTI) collection
> platform for Threat Hunting, OSINT, Brand/VIP monitoring, Dark/Deep Web
> monitoring, credential/IOC/card/leak/document hunting, campaign & threat
> actor discovery, correlation, scoring, enrichment, export and audit.

This document is the *source of truth* for the architecture. It is written
**before** the code and every module maps back to a decision described here.

---

## 1. Domain

The platform's bounded context is **Threat Intelligence Collection**. The
ubiquitous language:

| Term | Meaning |
| --- | --- |
| **Finding** | The single canonical unit of intelligence produced by the pipeline. Every connector, regardless of source, yields the *same* `Finding` model. |
| **Connector** | An adapter that connects to an external source and collects raw items. |
| **Indicator (IOC)** | An observable of compromise/interest: IP, domain, URL, hash, email, wallet, card, CPF/CNPJ, etc. |
| **Artifact** | A binary/textual attachment associated with a finding (screenshot, file, paste body). |
| **Detection** | A rule match (regex / keyword / IOC / YARA / Sigma / heuristic) against collected content. |
| **Score** | A configurable numeric weight expressing how relevant/dangerous a finding is. |
| **Watchlist / Keyword** | Managed monitoring terms: VIPs, brands, domains, threat actors, emails, documents, etc. |
| **Threat Actor** | An adversary entity discovered/monitored. |
| **Campaign** | A correlated cluster of related findings/indicators. |
| **Relationship** | A typed edge between two entities/indicators used by correlation. |

### Core domain invariants

1. A `Finding` is immutable in identity (`id`) but its enrichment fields evolve
   through the pipeline (score, tags, indicators, relationships).
2. Every `Indicator` is normalised (defanged input is refanged, casing folded)
   so deduplication and correlation are deterministic.
3. `severity`, `score` and `confidence` are always present and always inside
   their declared ranges (enforced by Pydantic validators).

---

## 2. Architectural decisions

### 2.1 Clean Architecture + Hexagonal (Ports & Adapters)

The dependency rule is absolute: **the core points inward only**.

```
        +-----------------------------------------------------+
        |                    infrastructure                   |
        |   connectors, parsers, storage, exporters, opsec,   |
        |   detection/scoring engines, observability, DI      |
        |     (ADAPTERS — implement core ports)               |
        +-----------------------------------------------------+
                         |  implements  ^
                         v              |  depends on (interfaces only)
        +-----------------------------------------------------+
        |                  core.application                   |
        |   ports (Protocols), pipeline orchestrator,         |
        |   use-case services, DTOs                           |
        +-----------------------------------------------------+
                         |  uses
                         v
        +-----------------------------------------------------+
        |                    core.domain                      |
        |  entities, value objects, domain events, rules      |
        |         (ZERO external/framework imports)           |
        +-----------------------------------------------------+
```

- `core.domain` imports **nothing** outside the standard library + Pydantic
  (Pydantic V2 is treated as a domain-modelling primitive, not infrastructure).
- `core.application` defines **ports** as `typing.Protocol` classes. It never
  imports `infrastructure`.
- `infrastructure` depends on `core`, never the reverse. This is verified by an
  automated architecture test (`tests/unit/test_architecture_boundaries.py`).

### 2.2 Domain Driven Design

Entities (`Finding`, `ThreatActor`, `Campaign`), value objects (`Indicator`,
`Artifact`, `Relationship`, `Score`, `Severity`), and aggregates keep business
rules where the data lives. No anemic models: validation and normalisation live
on the value objects themselves.

### 2.3 Event Driven

The pipeline publishes domain events (`FindingCollected`, `FindingScored`,
`FindingPersisted`, `HighSeverityFindingDetected`, …) through an `EventBus`
port. Observers (Observer Pattern) subscribe — e.g. the auto-MISP exporter
subscribes to `HighSeverityFindingDetected`. This decouples "what happened"
from "who reacts".

### 2.4 SOLID

- **S** — every engine is one responsibility (detection ≠ scoring ≠ dedup).
- **O** — new connectors/exporters/detections are added by *extension* (new
  class + auto-discovery), never by editing the core.
- **L** — every `BaseConnector` subclass is substitutable in the pipeline.
- **I** — ports are small and role-specific (`FindingRepository`,
  `Exporter`, `EnrichmentProvider`…), not one god-interface.
- **D** — high-level pipeline depends on abstractions (ports), concrete
  adapters are injected by the DI container.

---

## 3. Design Patterns (where & why)

| Pattern | Location | Purpose |
| --- | --- | --- |
| **Repository** | `core.application.ports.FindingRepository`, `infrastructure/storage/*` | Abstracts persistence; swapping SQLite↔Postgres↔JSON changes no business rule. |
| **Unit of Work** | `ports.UnitOfWork`, `infrastructure/storage/*` | Atomic multi-repository transactions. |
| **Strategy** | detection/scoring/dedup/correlation engines | Interchangeable algorithms selected at runtime/config. |
| **Factory** | `infrastructure/connectors/factory.py`, exporter/storage factories | Build adapters from config without callers knowing concrete classes. |
| **Builder** | `core.domain.entities.finding.FindingBuilder` | Fluent, validated construction of complex `Finding` aggregates. |
| **Adapter** | every connector, exporter, storage backend | Wrap external systems behind core ports. |
| **Command** | `cli/*` + `core.application.services` use-cases | Each CLI action is a command object invoking a use-case. |
| **Observer** | `EventBus` + subscribers | React to domain events (auto-export, metrics, audit). |
| **Plugin** | `infrastructure/connectors/registry.py` (auto-discovery via entry points + package scan) | Discover connectors/exporters without touching core. |
| **Dependency Injection** | `config/container.py` | Compose the object graph in one place. |

---

## 4. The Pipeline (mandatory order)

```
Connector → Parser → Extractor → Normalizer → Detection → Scoring
          → Correlation → Deduplication → Enrichment → Persistence → Export
```

Each stage implements a `PipelineStage` port and is fully decoupled: it takes a
`PipelineContext` (carrying the working `Finding` list + shared state) and
returns it. Stages are ordered by the orchestrator, are individually testable,
and can be enabled/disabled by configuration. A failure in one stage is
isolated (logged, metered, and — per policy — either skipped or aborts the run).

`PipelineContext` fields: `run_id`, `connector_name`, `raw_items`,
`findings`, `stats`, `started_at`, plus a mutable `state` dict for stage
hand-off.

---

## 5. Connector SDK

`BaseConnector` (Template Method) defines the collection lifecycle:

```python
connect() -> collect() -> parse() -> normalize() -> health() -> close()
```

- `collect()` yields `RawItem`s. `parse()`/`normalize()` produce provisional
  `Finding`s (later refined by the shared pipeline engines).
- Connectors declare metadata (`name`, `source`, `category`, `enabled`) via a
  class-level `ConnectorMeta`.
- The `ConnectorRegistry` **auto-discovers** every `BaseConnector` subclass in
  `infrastructure/connectors` (and installed entry-point plugins). No central
  list to edit — pure Open/Closed.
- Connectors receive an OPSEC `Transport` (network abstraction) and never open
  sockets directly, guaranteeing proxy/rate-limit policy is always applied.

---

## 6. OPSEC layer

An independent transport abstraction (`infrastructure/opsec`) sitting between
connectors and the network. Provides per-connector **profiles** configuring:
HTTP/HTTPS proxy, SOCKS5 proxy (e.g. Tor), external VPN hints, rotating
User-Agents, rate limiting, retries with exponential backoff, and secret-safe
credential handling. Connectors request a `Transport` from the `OpsecManager`;
the manager applies the right profile. Configuration is centralized in
`config/opsec.yml` — connectors never hold transport config themselves.

---

## 7. Storage & Export

- **Storage** is fully abstracted behind `FindingRepository` + `UnitOfWork`.
  Backends: in-memory, JSON, SQLite (stdlib), and pluggable
  Postgres/OpenSearch/Elasticsearch/Splunk/Parquet/S3 adapters that share the
  same ports. Business rules never change when the backend changes.
- **Exporters** implement the `Exporter` port: JSON, CSV, STIX 2.1, MISP,
  OpenCTI, Splunk, OpenSearch, Webhook, REST. When a finding's score crosses a
  configurable threshold, the `HighSeverityFindingDetected` event triggers the
  automatic MISP exporter (Observer + threshold policy).

---

## 8. Configuration, DI & Observability

- **Config**: Pydantic-`Settings` loaded from `config/*.yml` + environment.
  Scoring weights, detection rules, watchlists, OPSEC profiles and enabled
  connectors are all data, never hardcoded.
- **DI**: a single composition root (`config/container.py`) wires adapters to
  ports. Falls back to a lightweight built-in container when
  `dependency-injector` is not installed, so the core always runs.
- **Observability**: `structlog` structured JSON logging, Prometheus metrics
  (`findings_total`, `pipeline_stage_seconds`, `connector_errors_total`…),
  OpenTelemetry tracing hooks (no-op when the SDK is absent), and `HealthCheck`
  aggregation across connectors/storage.

---

## 9. Project structure

```
threat_hunting/
  core/
    domain/            # entities, value objects, events, exceptions (pure)
    application/        # ports (Protocols), pipeline, use-case services, DTOs
  infrastructure/
    connectors/         # BaseConnector SDK, registry (plugin), factory, sources
    parsers/            # raw -> structured
    extractors/         # IOC/indicator extraction
    normalizers/        # canonicalisation
    detections/         # detection engine + rule strategies (regex/keyword/ioc/yara/sigma)
    scoring/            # configurable weighted scoring engine
    correlation/        # entity/indicator correlation engine
    deduplication/      # dedup strategies (hash/similarity/ioc)
    enrichment/         # enrichment engine + providers
    opsec/              # transport abstraction, proxy/rate-limit profiles
    storage/            # repositories + unit of work (memory/json/sqlite/...)
    exporters/          # MISP/STIX/JSON/CSV/webhook/...
    events/             # in-memory event bus + subscribers
    observability/      # logging, metrics, tracing, health
    scheduler/          # APScheduler adapter (optional)
    keywords/           # watchlist / keyword management
  config/               # settings, DI container
  cli/                  # Typer CLI (`hunt ...`)
config/                 # YAML: connectors, scoring, rules, opsec, watchlists
tests/                  # unit + integration
docs/                   # this document + module docs
```

## 10. End-to-end flow

1. `hunt run <connector|group|all>` (CLI Command) invokes the
   `RunCollection` use-case via the DI container.
2. The use-case asks the `ConnectorRegistry` for the requested connector(s).
3. For each connector the `PipelineOrchestrator` runs the mandatory stages in
   order, publishing domain events at each transition.
4. Findings crossing the score threshold trigger auto-export via the event bus.
5. Findings are persisted through the `UnitOfWork`; metrics and structured logs
   are emitted throughout; a run summary is returned to the CLI.

## 11. Django-readiness

All management data (connectors, keywords, VIPs, actors, watchlists, rules,
scheduler, proxies, integrations, findings, exports, logs, metrics, jobs) lives
behind ports and Pydantic models. A future Django admin becomes *another
adapter* over the same application services — no core change required.
