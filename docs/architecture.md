# Threat Hunting Collection Architecture

## Domain

The domain models threat intelligence collection as canonical `Finding`
aggregates. A finding contains source metadata, normalized data, indicators,
artifacts, relationships, timeline events, tags, severity, confidence and score.
Connectors are not business entities; they are plugins that emit findings.

## Layers

- `core/domain`: Pydantic entities, value objects, domain events and exceptions.
- `core/application`: ports and use cases that express business contracts.
- `infrastructure`: adapters for configuration, OPSEC, logging, metrics, tracing,
  storage, scheduling, events and external integrations.
- `connectors`: SDK and plugin registry for source collection.
- `pipelines`: fixed orchestration of the mandatory hunting pipeline.
- `cli`: Typer commands that invoke application services.
- `api` and `web`: future administrative interfaces, including Django readiness.

## Contracts

The main ports are `BaseConnector`, `ParserPort`, `ExtractorPort`,
`NormalizerPort`, `DetectionEnginePort`, `ScoringEnginePort`,
`CorrelationEnginePort`, `DeduplicationEnginePort`, `EnrichmentEnginePort`,
`FindingRepository`, `UnitOfWork`, `ExporterPort`, `EventBus`,
`ConnectorRegistryPort`, `SecretsProvider` and `TransportFactory`.

## Patterns

- Clean Architecture and Hexagonal Architecture: core depends on abstractions.
- Domain Driven Design: `Finding` is the central aggregate.
- Repository and Unit of Work: persistence is behind contracts.
- Strategy: parser, detection, scoring, correlation, deduplication, enrichment
  and export algorithms can be swapped.
- Factory: connector, transport and exporter construction.
- Builder: connectors normalize payloads into canonical findings.
- Adapter: HTTP, SQLAlchemy, JSON, MISP, OpenTelemetry and Prometheus.
- Command: CLI and scheduler commands run application use cases.
- Observer: event bus publishes collection, persistence and export events.
- Plugin: connector discovery through entry points and config.

## Pipeline

Every execution follows this sequence:

1. Connector
2. Parser
3. Extractor
4. Normalizer
5. Detection Engine
6. Scoring Engine
7. Correlation Engine
8. Deduplication Engine
9. Enrichment Engine
10. Persistence
11. Export

## OPSEC

OPSEC profiles are centralized in YAML and provide HTTP, HTTPS, SOCKS5, VPN
handoff assumptions, user agents, retries, backoff and credential references.
Connectors receive transports from the OPSEC factory instead of constructing
network clients directly.

## Storage and exports

Storage is abstracted through repositories and Unit of Work. Current adapters
include memory, JSON and SQLAlchemy for SQLite/PostgreSQL. The same contract can
back OpenSearch, Elasticsearch, Splunk, Parquet, S3 and data lake targets.
Exporters are independent adapters for JSON, CSV, STIX 2.1, webhooks, MISP and
future OpenCTI, TAXII, SIEM or search destinations.
