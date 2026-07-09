# Threat Hunting Collection Architecture

## Domain

The platform domain is continuous cyber threat intelligence collection. The main aggregate is `Finding`, a canonical observation emitted by every connector. Supporting value objects are `Indicator`, `Artifact`, `Relationship`, and `TimelineEvent`. Managed business entities include `Watchlist`, `DetectionRule`, and `ScoringProfile` for keywords, VIPs, brands, domains, actors, documents, CPF/CNPJ, cards, wallets, YARA, Sigma, Regex, and IOC lists.

## Architectural decisions

- Clean Architecture and Hexagonal Architecture keep domain/application code independent from databases, HTTP clients, MISP, OpenCTI, Redis, schedulers, and CLIs.
- Domain Driven Design keeps ubiquitous concepts explicit: finding, indicator, artifact, rule, watchlist, score, correlation, enrichment, export.
- Event Driven design emits domain events after persistence so audit, logs, metrics, and exports can observe without coupling.
- Configuration-driven rules prevent hardcoded detections and make Django administration possible later.
- OPSEC is an infrastructure adapter, not connector logic. Connectors receive a transport configured with proxies, user-agent, retries, backoff, rate limiting, and credential references.

## Patterns

- Repository Pattern: `FindingRepository`.
- Unit of Work: transactional persistence boundary.
- Dependency Injection: `ApplicationContainer`.
- Strategy Pattern: detection, scoring, correlation, deduplication, enrichment, exporters.
- Factory Pattern: connector registry and OPSEC transport factory.
- Builder Pattern: DI container assembles pipelines from settings.
- Adapter Pattern: storage, HTTP transport, exporters, integrations.
- Command Pattern: CLI and scheduler send command objects to use cases.
- Observer Pattern: `EventBus` publishes domain events.
- Plugin Pattern: connector registry discovers built-ins, modules, and entry points.

## Project structure

- `threat_hunting/core/domain`: pure entities, value objects, rules, events.
- `threat_hunting/core/application`: ports, commands, use cases, pipeline orchestration.
- `threat_hunting/infrastructure`: configuration, DI, OPSEC, logging, observability.
- `threat_hunting/connectors`: connector SDK, built-ins, plugin registry.
- `threat_hunting/parsers`: parser contracts.
- `threat_hunting/extractors`: artifact and IOC extraction strategies.
- `threat_hunting/normalizers`: canonical finding normalization.
- `threat_hunting/detections`: dynamic detection engine.
- `threat_hunting/scoring`: configurable scoring engine.
- `threat_hunting/correlation`: automatic relationship engine.
- `threat_hunting/deduplication`: duplicate elimination engine.
- `threat_hunting/enrichment`: contextual enrichment.
- `threat_hunting/pipelines`: public pipeline facade.
- `threat_hunting/scheduler`: APScheduler adapter.
- `threat_hunting/plugins`: plugin discovery facade.
- `threat_hunting/storage`: memory, JSON, and SQLAlchemy persistence adapters.
- `threat_hunting/exporters`: MISP/OpenCTI/Splunk/OpenSearch/Webhook/JSON/CSV/STIX/TAXII export adapters.
- `threat_hunting/integrations`: external service adapters such as MISP.
- `threat_hunting/cli`: Typer CLI.
- `threat_hunting/api` and `threat_hunting/web`: future API and Django administration adapters.
- `config`: YAML configuration.
- `tests`: unit and integration tests.

## Flow

1. CLI, scheduler, API, or future Django admin sends a command.
2. The use case resolves one connector or a connector group.
3. The connector collects raw data through an OPSEC transport.
4. Parser converts source payloads to intermediate records.
5. Extractor identifies artifacts and indicators.
6. Normalizer emits canonical `Finding`.
7. Detection engine evaluates dynamic rules.
8. Scoring engine applies configured weights and severity thresholds.
9. Correlation engine links shared infrastructure, identities, campaigns, actors, and IOCs.
10. Deduplication engine eliminates repeated records by hash, IOC overlap, and textual similarity.
11. Enrichment engine adds contextual intelligence.
12. Repository and Unit of Work persist the aggregate.
13. Event bus publishes audit/metric/export events.
14. Exporters send high-score findings to enabled destinations.
