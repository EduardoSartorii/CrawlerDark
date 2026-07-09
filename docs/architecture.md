# Threat Hunting Platform - Architecture

## 1. Architectural vision

This platform is built as a long-lived corporate product with strict boundaries between
domain, application, and infrastructure concerns. The design combines:

- Clean Architecture
- Domain-Driven Design
- Hexagonal Architecture
- Event-driven processing
- Explicit dependency inversion

The core business logic is framework-agnostic and independent from persistence, network,
and external APIs.

## 2. Domain boundaries

### Collection Context
- Connector orchestration
- Source health checks
- OPSEC profile selection

### Detection Context
- Dynamic rule loading
- Rule execution pipeline
- IOC/actor/keyword matching

### Intelligence Context
- Scoring
- Correlation
- Deduplication
- Enrichment

### Governance Context
- Audit trail
- Execution telemetry
- Connector lifecycle control

## 3. Canonical model

All connectors emit data into a canonical `Finding` model. Every stage in the pipeline
reads and writes this model only. This creates a stable anti-corruption boundary for
heterogeneous sources.

## 4. Processing pipeline

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

Each stage is represented by a dedicated contract in `core/contracts.py`.

## 5. Patterns and usage

- **Repository Pattern**: persistence abstractions for findings/rules.
- **Unit of Work**: transactional boundary for writes.
- **Strategy Pattern**: detection/scoring/correlation/dedup/enrichment implementations.
- **Factory Pattern**: connector and pipeline stage construction.
- **Builder Pattern**: normalized finding assembly from raw data.
- **Adapter Pattern**: external systems (MISP, OpenCTI, transport clients).
- **Command Pattern**: CLI and scheduler commands.
- **Observer Pattern**: event subscriptions on domain events.
- **Plugin Pattern**: connector auto-discovery without core edits.

## 6. OPSEC layer

Connectors do not instantiate HTTP clients directly. They consume an OPSEC transport
service that supports:

- HTTP/HTTPS proxies
- SOCKS5 proxies
- user-agent profiles
- retry/backoff/rate-limiting
- externally managed VPN assumptions
- central credential references

## 7. Storage and export abstraction

Storage and export backends are contract-based and swappable. Business rules remain
unchanged when switching from SQLite/PostgreSQL to search backends or data lake targets.

## 8. Django readiness

A future Django admin can consume the same application use cases, repositories, and
domain contracts. The web layer will be an inbound adapter, not a rewrite.
