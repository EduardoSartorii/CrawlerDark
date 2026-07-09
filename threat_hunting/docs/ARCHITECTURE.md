# Architecture Decision Record — Threat Hunting Platform

## Overview

The Threat Hunting Platform is built on **Clean Architecture + Domain-Driven Design + Hexagonal Architecture**.

## Layer Model

```
┌──────────────────────────────────────────────────────────┐
│                    CLI / API / Web                        │  ← Delivery
├──────────────────────────────────────────────────────────┤
│                  Application Layer                        │  ← Use Cases, Commands
│              (RunCollectionUseCase, etc.)                 │
├──────────────────────────────────────────────────────────┤
│                    Domain Layer                           │  ← Entities, Value Objects
│   Finding | Indicator | Keyword | ThreatActor | Rule     │
│   Score | Severity | ThreatCategory | SourceType         │
├──────────────────────────────────────────────────────────┤
│                Infrastructure Layer                       │  ← Adapters
│  Connectors | Engines | Storage | Exporters | OPSEC      │
└──────────────────────────────────────────────────────────┘
```

## Design Patterns Applied

| Pattern | Where | Purpose |
|---------|-------|---------|
| Clean Architecture | Full stack | Dependency inversion, testability |
| DDD | Domain layer | Rich domain model, bounded contexts |
| Hexagonal | Core ↔ Infra | Ports & Adapters |
| Repository | Storage | Abstract persistence |
| Unit of Work | SQLAlchemy | Transaction boundaries |
| Strategy | Engines | Pluggable detection/scoring rules |
| Factory | Finding.create() | Controlled entity construction |
| Plugin | ConnectorRegistry | Auto-discovery of connectors |
| Template Method | BaseConnector.run() | Fixed skeleton, customizable steps |
| Builder | ScoringWeights | Composable configuration |
| Observer | Domain Events | Loose coupling between aggregates |
| Command | CLI Commands | Encapsulated operations |

## Collection Pipeline

```
Connector.run()
     ↓
Detection Engine   (regex, YARA, keyword, IOC, heuristic rules)
     ↓
Enrichment Engine  (domain extractor, watchlist matcher, actor matcher)
     ↓
Scoring Engine     (weighted multi-factor risk score)
     ↓
Correlation Engine (inverted-index, attribute-based relationship discovery)
     ↓
Deduplication      (fingerprint + fuzzy similarity)
     ↓
Storage (UoW)      (SQLite / PostgreSQL via SQLAlchemy 2.0 async)
     ↓
Export             (JSON, CSV, STIX 2.1, MISP)
```

## Key Invariants

1. **Core domain has zero infrastructure imports**
2. **All findings pass through the same normalized model (Finding)**
3. **Detection rules are data, not code — loaded dynamically**
4. **OPSEC layer is transparent to connectors**
5. **Connectors never touch storage directly**
6. **Domain events are dispatched after transaction commit, never during**
