# Threat Hunting Collection Platform — Architecture

> A modular, production-oriented Cyber Threat Intelligence (CTI) collection
> platform. This document explains the domain, the architectural decisions, the
> entities, the contracts, the design patterns, the project structure and the
> full application flow. **Read this before reading the code.**

---

## 1. Domain

The bounded context of this platform is **Threat Intelligence Collection**.

Whatever the source — Reddit, GitHub, an RSS feed, a paste site, a dark-web
forum or a threat-intel feed such as ThreatFox — the platform collects raw
content, extracts indicators, evaluates it against detection rules, scores it,
correlates it with previously seen intelligence, removes duplicates, enriches it
and finally persists and exports it.

The **ubiquitous language** of the domain:

| Term | Meaning |
| --- | --- |
| **Finding** | The canonical unit of intelligence. Every connector produces the *same* `Finding` shape. |
| **Indicator (IOC)** | An atomic observable: IP, domain, URL, hash, email, CPF, CNPJ, card, wallet, etc. |
| **Artifact** | A collected object attached to a finding (screenshot, file, raw HTML). |
| **Relationship** | A typed edge between findings/indicators/actors (correlation output). |
| **Timeline event** | An auditable event in the life of a finding. |
| **Connector** | An adapter that collects from one source. |
| **Watchlist / Keyword / VIP / Brand / ThreatActor / Campaign** | The hunting targets that drive detection and scoring. |
| **Detection rule** | A dynamically loaded rule (regex / keyword / IOC / YARA / Sigma). |

The **Finding aggregate** is the consistency boundary: indicators, artifacts,
relationships and timeline events belong to a finding and are never mutated
outside of it.

---

## 2. Architectural decisions

1. **Clean Architecture + Hexagonal (Ports & Adapters).**
   The business rules live in `core` and know nothing about databases, HTTP,
   MISP or the CLI. Every external concern is reached through a **port**
   (an abstract interface). Infrastructure provides **adapters** for those
   ports. This is what makes "swapping the storage backend does not change a
   single business rule" literally true.

2. **The Dependency Rule.** Source-code dependencies always point inward:
   `cli → infrastructure → application → domain`. `domain` imports nothing from
   the platform except the standard library and Pydantic. A CI guard test
   (`tests/unit/test_architecture.py`) enforces this.

3. **Domain-Driven Design.** The `Finding` aggregate, value objects
   (`Score`, `Severity`, `Confidence`) and domain events model the language of
   CTI analysts, not the language of any framework.

4. **Event-Driven.** Each pipeline milestone publishes a domain event on an
   `EventBus` (Observer). Exporters, metrics and audit logging subscribe to
   those events, so adding a new reaction never touches the pipeline.

5. **Plugin architecture for collection.** Connectors are discovered
   automatically at runtime (entry points + package scanning). A new source is
   *only* a new subclass of `BaseConnector`; the core is never edited.

6. **Configuration over code.** Detection rules, scoring weights, OPSEC
   profiles and connector settings are declared in YAML and loaded at runtime.
   Nothing is hardcoded.

7. **Prepared for a Django admin.** All management concepts (connectors,
   keywords, VIPs, rules, scheduler, proxies, findings, exports) are modelled as
   domain/config objects behind ports, so a future Django project can drive the
   same use cases without re-implementing business logic.

---

## 3. Entities & value objects (`core/domain`)

- **Value objects** (`enums.py`, `value_objects.py`):
  `Severity`, `Category`, `ConfidenceLevel`, `IndicatorType`, `RelationshipType`,
  `ConnectorStatus`, `Score` (0–100, immutable, with weighted composition).
- **Entities** (`entities.py`):
  `Indicator`, `Artifact`, `Relationship`, `TimelineEvent`, and the
  `Finding` aggregate root with exactly the requested fields:
  `id, title, description, source, connector, category, severity, score,
  confidence, created_at, updated_at, raw_data, normalized_data, metadata,
  tags, artifacts, indicators, relationships, timeline`.
- **Hunting targets** (`watchlist.py`):
  `Keyword`, `Watchlist`, `VIP`, `Brand`, `ThreatActor`, `Campaign`.
- **Domain events** (`events.py`): `FindingCollected`, `FindingDetected`,
  `FindingScored`, `FindingCorrelated`, `FindingDeduplicated`,
  `FindingEnriched`, `FindingPersisted`, `FindingExported`.

---

## 4. Contracts (`core/application/ports`)

All ports are `abc.ABC` / `typing.Protocol` definitions with full type hints:

- **Collection**: `ConnectorPort` (`connect/collect/parse/normalize/health/close`).
- **Pipeline stages**: `ParserPort`, `ExtractorPort`, `NormalizerPort`,
  `DetectionEnginePort`, `ScoringEnginePort`, `CorrelationEnginePort`,
  `DeduplicationEnginePort`, `EnrichmentEnginePort`.
- **Persistence**: `FindingRepositoryPort`, `UnitOfWorkPort`.
- **Export**: `ExporterPort`.
- **Messaging**: `EventBusPort`, `EventHandler`.
- **OPSEC**: `TransportPort`, `TransportFactoryPort`.
- **Rules**: `RuleRepositoryPort`, `WatchlistRepositoryPort`.

The core depends only on these abstractions. Concrete classes are injected.

---

## 5. Design patterns

| Pattern | Where |
| --- | --- |
| Repository | `FindingRepositoryPort` + SQLAlchemy / JSON / in-memory adapters |
| Unit of Work | `UnitOfWorkPort` wrapping a repository + transaction |
| Strategy | detection rules, scoring contributors, exporters |
| Factory | `ConnectorFactory`, `ExporterFactory`, `TransportFactory` |
| Builder | the pipeline incrementally builds each `Finding` |
| Adapter | every connector and storage backend |
| Command | each pipeline stage is a discrete, replaceable step |
| Observer | `EventBus` + subscribers (audit, metrics, auto-export) |
| Plugin | `ConnectorRegistry` auto-discovery |
| Chain of Responsibility | `Pipeline.execute()` runs the ordered stages |
| Dependency Injection | `infrastructure/di/container.py` composition root |

---

## 6. Project structure

```
threat_hunting/
  core/
    domain/                 # entities, value objects, events (no I/O)
    application/
      ports/                # contracts (ABC/Protocol)
      use_cases/            # RunHunt, ExportFindings
      pipeline.py           # the decoupled orchestrator
      dto.py                # PipelineContext, RawRecord
  infrastructure/
    connectors/             # BaseConnector SDK + registry + builtins/
    parsers/                # RawRecord -> structured text
    extractors/             # IOC extraction (regex)
    normalizers/            # canonical normalized_data
    detections/             # detection engine + rule strategies
    scoring/                # configurable scoring engine
    correlation/            # relationship inference
    deduplication/          # hash + textual similarity
    enrichment/             # indicator enrichment
    storage/                # SQLAlchemy models, repos, UoW
    exporters/              # JSON, CSV, STIX 2.1, MISP
    opsec/                  # transport, proxies, rate-limit, retry
    events/                 # in-memory event bus
    observability/          # structlog, prometheus, health, tracing
    config/                 # pydantic settings + YAML loader
    di/                     # composition root (dependency-injector)
    scheduler/              # APScheduler adapter
  cli/                      # Typer app ("hunt ...")
  plugins/                  # drop-in external connectors
config/                     # settings.yml, scoring.yml, rules/*.yml
tests/                      # unit + integration
docs/                       # this document
```

> **Mapping note.** The task lists `connectors/`, `parsers/`, `scoring/`, … as
> siblings. In Clean Architecture these are *adapters*, so they live under
> `infrastructure/` to make the dependency direction explicit. The names and
> responsibilities are identical to the requested layout.

---

## 7. Full application flow

```
                 ┌──────────────────────────────────────────────┐
   hunt run rss  │                RunHuntUseCase                 │
 ───────────────▶│  resolves connector via ConnectorRegistry     │
                 └───────────────┬──────────────────────────────┘
                                 │ RawRecord[]
                                 ▼
   Connector.collect()  ─▶  Parser  ─▶  Extractor  ─▶  Normalizer
   (OPSEC transport)         (text)     (IOCs)         (normalized_data)
                                 │
                                 ▼
   Detection ─▶ Scoring ─▶ Correlation ─▶ Deduplication ─▶ Enrichment
   (rules)      (weights)  (relationships) (hash/similar)   (context)
                                 │
                                 ▼
        UnitOfWork.persist(Finding)  ──(FindingPersisted event)──▶ EventBus
                                 │                                    │
                                 ▼                                    ▼
        Exporters (JSON/CSV/STIX/MISP)                     Audit log / Metrics
        auto-MISP if score >= threshold
```

Each arrow is a **port** call, so any stage can be replaced, disabled or
re-ordered through configuration without editing another stage. Every stage
emits a structured log line and a Prometheus metric, and publishes a domain
event consumed by the observer subscribers.
