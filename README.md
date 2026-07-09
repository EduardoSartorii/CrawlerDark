# Threat Hunting Collection

Enterprise Threat Hunting Collection platform for OSINT, brand monitoring, VIP
monitoring, dark web monitoring, credential hunting, IOC discovery, correlation,
scoring, enrichment, persistence and export.

## Architecture

The project follows Clean Architecture, DDD and Hexagonal Architecture:

- `threat_hunting/core/domain`: canonical `Finding`, indicators, artifacts,
  relationships, rules, score policies and domain events.
- `threat_hunting/core/application`: ports and use cases.
- `threat_hunting/infrastructure`: adapters for config, OPSEC, logging,
  observability, events, storage, scheduler and integrations.
- `threat_hunting/connectors`: connector SDK and plugin registry.
- `threat_hunting/pipelines`: mandatory hunting pipeline.
- `threat_hunting/cli`: Typer commands.

See `docs/architecture.md` for domain, contracts, patterns and flow.

## Install

```bash
poetry install
```

## CLI

```bash
hunt run reddit
hunt run github
hunt run telegram
hunt run social
hunt run darkweb
hunt run all
hunt connector enable reddit
hunt connector disable reddit
hunt scheduler run
hunt export misp
hunt export splunk
hunt export elastic
hunt score test
```

## Configuration

Runtime settings live in `config/default.yml`:

- connectors and plugin types;
- OPSEC profiles with proxies, SOCKS5, user agents, retries and backoff;
- dynamic detection rules;
- scoring weights and export thresholds;
- watchlists for keywords, VIPs, brands, domains, actors, documents and IOCs;
- storage and exporters.

## Connector SDK

Every connector must inherit `BaseConnector` and implement:

- `connect()`
- `collect()`
- `parse()`
- `normalize()`
- `health()`
- `close()`

New connectors can be discovered through the `threat_hunting.connectors` entry
point group without modifying the core.

## Tests

```bash
poetry run pytest
```
