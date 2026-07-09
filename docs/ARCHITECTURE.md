# Threat Hunting Collection Platform — Architecture

> **Documento obrigatório.** Este arquivo define o domínio, as decisões arquiteturais,
> entidades, contratos, design patterns, estrutura e fluxo completo da aplicação.
> Nenhum módulo de código deve ser interpretado sem este contexto.

---

## 1. Visão Geral

A plataforma é um sistema corporativo de **Threat Hunting Collection** para descoberta
automática de ameaças, vazamentos, campanhas, IOCs, monitoramento de marca/VIP,
Dark/Deep Web e coleta multi-fonte de inteligência.

Ela **não** é um conjunto de scripts. É uma plataforma modular, event-driven,
orientada a domínio, preparada para CLI, scheduler e futura UI administrativa Django.

### Princípios inegociáveis

| Princípio | Implicação |
|-----------|------------|
| Clean Architecture | Dependências apontam sempre para dentro (Domain) |
| Hexagonal | Ports (interfaces) no Core; Adapters na Infrastructure |
| DDD | Bounded contexts claros; linguagem ubíqua |
| SOLID | Especialmente OCP para conectores/plugins |
| Event Driven | Domain events desacoplam side-effects |
| Plugin Pattern | Conectores descobertos dinamicamente; Core nunca muda |

---

## 2. Domínio da Aplicação

### 2.1 Bounded Contexts

```
┌─────────────────────────────────────────────────────────────────┐
│                    Threat Hunting Platform                       │
├──────────────┬──────────────┬──────────────┬────────────────────┤
│  Collection  │  Detection   │ Intelligence │   Governance       │
│  Context     │  Context     │ Context      │   Context          │
├──────────────┼──────────────┼──────────────┼────────────────────┤
│ Connectors   │ Regex/YARA   │ Correlation  │ Keywords/VIPs      │
│ Parsers      │ Sigma/IOC    │ Scoring      │ Watchlists         │
│ Extractors   │ Heuristics   │ Enrichment   │ Audit/RBAC         │
│ OPSEC        │ Whitelist/BL │ Dedup        │ Scheduler/Jobs     │
│ Pipeline     │ Rules Engine │ Export/STIX  │ Observability      │
└──────────────┴──────────────┴──────────────┴────────────────────┘
```

### 2.2 Linguagem Ubíqua

| Termo | Significado |
|-------|-------------|
| **Finding** | Unidade canônica de inteligência produzida por qualquer conector |
| **Connector** | Adapter de coleta de uma fonte externa |
| **Artifact** | Evidência bruta anexada (HTML, screenshot, arquivo) |
| **Indicator (IOC)** | Indicador de comprometimento tipado (IP, domain, hash, email…) |
| **Watchlist** | Conjunto nomeado de keywords/entidades monitoradas |
| **VIP** | Pessoa de alto valor monitorada (executivo, celebridade) |
| **Campaign** | Agrupamento correlacionado de findings |
| **Threat Actor** | Atribuído ou suspeito autor de ameaça |
| **Hunt Job** | Execução unitária de coleta + pipeline |
| **Score** | Valor numérico de risco/relevância do Finding |
| **OPSEC Profile** | Perfil de transporte seguro (proxy, UA, rate limit) |

---

## 3. Decisões Arquiteturais

### ADR-001 — Clean Architecture + Hexagonal

- **Context:** Necessidade de trocar backends (SQLite↔PostgreSQL↔OpenSearch) e fontes
  sem alterar regras de negócio.
- **Decision:** Domain e Application no centro; Infrastructure e Connectors como
  adapters. Ports definidos como Protocol/ABC no Core.
- **Consequence:** Core nunca importa `sqlalchemy`, `httpx`, `redis`, etc.

### ADR-002 — Finding como Aggregate Root canônico

- **Context:** Fontes heterogêneas (Reddit, MISP, Dark Web…) produzem formatos distintos.
- **Decision:** Todo conector normaliza para o modelo `Finding`. Downstream engines
  operam exclusivamente sobre Findings.
- **Consequence:** Um único contrato; parsers/extractors/normalizers por fonte.

### ADR-003 — Pipeline desacoplado por estágios

- **Context:** Necessidade de evoluir Detection/Scoring/Correlation independentemente.
- **Decision:** Pipeline Orchestrator com estágios Strategy-based, cada um com
  interface própria e injeção via DI.
- **Consequence:** Estágios testáveis isoladamente; ordem fixa e configurável.

### ADR-004 — Plugin Discovery para Conectores

- **Context:** Novas fontes devem ser adicionadas sem tocar no Core.
- **Decision:** `BaseConnector` + entry-point / filesystem discovery + registry.
- **Consequence:** `hunt run <name>` resolve dinamicamente; enable/disable via config.

### ADR-005 — OPSEC como camada transversal

- **Context:** Coleta sensível exige proxies, SOCKS5, UA, rate limit, credenciais.
- **Decision:** `OpsecTransport` abstrai rede; perfis por conector em YAML centralizado.
- **Consequence:** Conectores pedem HTTP via port; nunca configuram proxy diretamente.

### ADR-006 — Preparação para Django Admin

- **Context:** UI administrativa futura.
- **Decision:** Modelos de domínio e repositórios já mapeáveis; camada `web/`
  reservada; entidades de governance (User, Permission, Job) no domínio.
- **Consequence:** Django será adapter de apresentação, não dono do domínio.

### ADR-007 — Event Driven para side-effects

- **Context:** Export automático MISP, métricas, auditoria.
- **Decision:** Domain Events (`FindingCreated`, `ScoreThresholdExceeded`, …)
  publicados via Event Bus (Observer). Handlers na Application/Infrastructure.
- **Consequence:** Export/audit não acoplados ao pipeline síncrono.

---

## 4. Entidades e Value Objects

### 4.1 Aggregate Roots

```
Finding (AR)
├── id: FindingId
├── title, description
├── source, connector
├── category: FindingCategory
├── severity: Severity
├── score: Score
├── confidence: Confidence
├── created_at, updated_at
├── raw_data: dict
├── normalized_data: dict
├── metadata: FindingMetadata
├── tags: list[Tag]
├── artifacts: list[Artifact]
├── indicators: list[Indicator]
├── relationships: list[Relationship]
└── timeline: list[TimelineEvent]

Watchlist (AR)
├── id, name, type, entries, enabled

ThreatActor (AR)
├── id, name, aliases, ttps, confidence

Campaign (AR)
├── id, name, findings[], actors[], iocs[]

HuntJob (AR)
├── id, connector, status, started_at, finished_at, stats

ConnectorConfig (AR)
├── name, enabled, opsec_profile, schedule, options
```

### 4.2 Value Objects / Enums

- `FindingId`, `IndicatorType`, `Severity`, `FindingCategory`
- `Score`, `Confidence`, `Tag`, `Artifact`, `Indicator`
- `Relationship`, `TimelineEvent`, `OpsecProfile`
- `Keyword`, `VipProfile`, `Brand`, `Domain`, `Wallet`

### 4.3 Domain Events

- `FindingCreated`, `FindingScored`, `FindingCorrelated`
- `FindingDeduplicated`, `FindingEnriched`, `FindingPersisted`
- `ScoreThresholdExceeded`, `ExportRequested`, `HuntJobCompleted`
- `ConnectorHealthFailed`, `AuditRecorded`

---

## 5. Contratos (Ports)

### 5.1 Collection

```python
class BaseConnector(ABC):
    async def connect(self) -> None: ...
    async def collect(self) -> AsyncIterator[RawDocument]: ...
    async def parse(self, raw: RawDocument) -> ParsedDocument: ...
    async def normalize(self, parsed: ParsedDocument) -> Finding: ...
    async def health(self) -> HealthStatus: ...
    async def close(self) -> None: ...
```

### 5.2 Pipeline Stages

```python
ParserPort / ExtractorPort / NormalizerPort
DetectionEnginePort / ScoringEnginePort
CorrelationEnginePort / DeduplicationEnginePort / EnrichmentEnginePort
```

### 5.3 Persistence (Repository + UoW)

```python
FindingRepositoryPort
WatchlistRepositoryPort
ThreatActorRepositoryPort
HuntJobRepositoryPort
UnitOfWorkPort
```

### 5.4 Storage Backends (abstract)

```python
StorageBackendPort  # SQLite | PostgreSQL | OpenSearch | ES | Splunk | JSON | Parquet | S3
```

### 5.5 Export / Integration

```python
ExporterPort  # MISP | OpenCTI | Splunk | OpenSearch | Webhook | REST | JSON | CSV | STIX | TAXII
```

### 5.6 OPSEC / Transport

```python
OpsecTransportPort
CredentialVaultPort
RateLimiterPort
```

### 5.7 Observability

```python
MetricsPort / TracerPort / HealthCheckPort / AuditPort
```

---

## 6. Design Patterns Utilizados

| Pattern | Onde | Por quê |
|---------|------|---------|
| **Repository** | `core/domain/repositories` | Abstrair persistência |
| **Unit of Work** | `core/application/uow` | Transações atômicas multi-repo |
| **Dependency Injection** | `infrastructure/di` | Wiring sem acoplamento |
| **Strategy** | Detection/Scoring rules, Exporters | Troca de algoritmo em runtime |
| **Factory** | ConnectorFactory, ExporterFactory | Criação tipada por nome |
| **Builder** | FindingBuilder, HuntJobBuilder | Construção complexa imutável |
| **Adapter** | Connectors, Storage backends | Adaptar APIs externas ao Port |
| **Command** | CLI + Application Commands | Encapsular intenções (`RunHuntCommand`) |
| **Observer** | Event Bus | Reagir a domain events |
| **Plugin** | Connector Registry | Extensão sem modificar Core |
| **Template Method** | BaseConnector | Fluxo connect→collect→parse→normalize |
| **Chain of Responsibility** | Pipeline stages | Encadeamento de processamento |

---

## 7. Estrutura Completa do Projeto

```
threat_hunting/
├── pyproject.toml
├── README.md
├── docs/
│   ├── ARCHITECTURE.md          # Este documento
│   ├── CONNECTORS.md
│   ├── PIPELINE.md
│   └── DJANGO_PREP.md
├── config/
│   ├── settings.yaml
│   ├── scoring.yaml
│   ├── detection/
│   │   ├── regex.yaml
│   │   ├── keywords.yaml
│   │   ├── iocs.yaml
│   │   └── rules.yaml
│   ├── connectors/
│   │   └── *.yaml
│   └── opsec/
│       └── profiles.yaml
├── threat_hunting/
│   ├── __init__.py
│   ├── core/
│   │   ├── domain/
│   │   │   ├── entities/
│   │   │   ├── value_objects/
│   │   │   ├── enums/
│   │   │   ├── events/
│   │   │   ├── repositories/    # Ports (ABC)
│   │   │   └── services/        # Domain services
│   │   └── application/
│   │       ├── commands/
│   │       ├── handlers/
│   │       ├── use_cases/
│   │       ├── pipeline/
│   │       ├── ports/           # Application ports
│   │       ├── dto/
│   │       └── uow.py
│   ├── infrastructure/
│   │   ├── di/
│   │   ├── persistence/
│   │   │   ├── sqlalchemy/
│   │   │   ├── opensearch/
│   │   │   ├── json_store/
│   │   │   └── parquet_store/
│   │   ├── opsec/
│   │   ├── messaging/
│   │   ├── observability/
│   │   ├── config/
│   │   └── scheduler/
│   ├── connectors/
│   │   ├── base.py
│   │   ├── registry.py
│   │   ├── social/          # reddit, facebook, instagram, x, telegram, discord
│   │   ├── code/            # github, gitlab
│   │   ├── web/             # rss, blogs, sites, news, paste
│   │   ├── darkweb/         # darkweb, deepweb, forums, marketplaces
│   │   ├── feeds/           # feeds, apis
│   │   └── threat_intel/    # misp, opencti, threatfox, greynoise, vt, …
│   ├── parsers/
│   ├── extractors/
│   ├── normalizers/
│   ├── detections/
│   ├── scoring/
│   ├── correlation/
│   ├── deduplication/
│   ├── enrichment/
│   ├── pipelines/
│   ├── exporters/
│   ├── integrations/
│   ├── plugins/
│   ├── storage/
│   ├── cli/
│   ├── api/                 # Future FastAPI/REST
│   ├── web/                 # Future Django admin
│   └── database/
│       └── alembic/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── conftest.py
└── main.py                  # Legacy crawler (preserved)
```

---

## 8. Fluxo Completo da Aplicação

```
┌──────────┐   hunt run <connector>    ┌─────────────────┐
│   CLI    │ ─────────────────────────►│ RunHuntCommand  │
│ (Typer)  │                           │   (Application) │
└──────────┘                           └────────┬────────┘
                                                │
                    ┌───────────────────────────▼──────────────────────────┐
                    │              Pipeline Orchestrator                    │
                    │                                                      │
                    │  1. ConnectorFactory.resolve(name)                   │
                    │  2. OpsecTransport.bind(profile)                     │
                    │  3. connector.connect() → collect()                  │
                    │         │                                            │
                    │         ▼                                            │
                    │  Parser → Extractor → Normalizer → Finding           │
                    │         │                                            │
                    │         ▼                                            │
                    │  DetectionEngine  (regex/yara/sigma/keyword/ioc…)    │
                    │         │                                            │
                    │         ▼                                            │
                    │  ScoringEngine    (pesos configuráveis)              │
                    │         │                                            │
                    │         ▼                                            │
                    │  CorrelationEngine (domains/ips/actors/campaigns…)   │
                    │         │                                            │
                    │         ▼                                            │
                    │  DeduplicationEngine (hash/similarity/ioc…)          │
                    │         │                                            │
                    │         ▼                                            │
                    │  EnrichmentEngine (VT/OTX/GreyNoise/…)               │
                    │         │                                            │
                    │         ▼                                            │
                    │  Persistence (UoW + Repository)                      │
                    │         │                                            │
                    │         ▼                                            │
                    │  Domain Events → Export Handlers (MISP se threshold) │
                    └──────────────────────────────────────────────────────┘
                                                │
                    ┌───────────────────────────▼──────────────────────────┐
                    │  Observability: structlog + OTel + Prometheus        │
                    │  Audit trail + Health checks                         │
                    └──────────────────────────────────────────────────────┘
```

### Fluxo de um Finding (ciclo de vida)

1. **RawDocument** coletado pelo Connector (via OpsecTransport)
2. **ParsedDocument** estruturado pelo Parser
3. **ExtractedEntities** (IOCs, emails, cards…) pelo Extractor
4. **Finding** canônico pelo Normalizer (+ FindingBuilder)
5. **Detections** anexadas (matches de regras dinâmicas)
6. **Score/Confidence** calculados
7. **Relationships** correlacionadas
8. **Dedup** — merge ou discard se duplicata
9. **Enrichment** — reputação, WHOIS, VT, etc.
10. **Persist** via UnitOfWork
11. Se `score >= threshold` → evento `ScoreThresholdExceeded` → export MISP automático
12. Audit + Metrics + Tracing em cada estágio

---

## 9. Camada OPSEC

Configuração centralizada em `config/opsec/profiles.yaml`:

```yaml
profiles:
  default:
    proxy: null
    user_agent: "ThreatHuntingBot/1.0"
    rate_limit_rps: 1.0
    max_retries: 3
    backoff_factor: 2.0
  darkweb:
    proxy: "socks5h://127.0.0.1:9050"
    user_agent: "Mozilla/5.0 …"
    rate_limit_rps: 0.2
  social:
    proxy: "http://corp-proxy:8080"
    credentials_ref: "vault://social/reddit"
```

Conectores referenciam apenas o nome do perfil. Credenciais via `CredentialVaultPort`.

---

## 10. Storage Abstraction

```
StorageBackendPort
├── SqlAlchemyBackend (SQLite / PostgreSQL)
├── OpenSearchBackend
├── ElasticsearchBackend
├── SplunkBackend
├── JsonFileBackend
├── ParquetBackend
├── S3Backend / DataLakeBackend
```

Repositories usam o backend injetado. Troca via `config/settings.yaml` → DI container.

---

## 11. Detection & Scoring (regras dinâmicas)

- Regras em YAML/JSON sob `config/detection/`
- Carregadas em runtime por `RuleLoader` (Strategy registry)
- Scoring weights em `config/scoring.yaml`
- Nenhuma regra hardcoded no código Python

---

## 12. Preparação Django

- Entidades de governance já no domínio
- `threat_hunting/web/` reservado para Django project futuro
- Repositórios e UoW reutilizáveis pelos Django views/admin
- Documentado em `docs/DJANGO_PREP.md`

---

## 13. Observabilidade

| Capacidade | Tecnologia |
|------------|------------|
| Logging estruturado | structlog |
| Metrics | prometheus_client |
| Tracing | OpenTelemetry |
| Health | `/health` + CLI `hunt health` |
| Audit | AuditPort → storage |

---

## 14. Testes

- Unitários: domain, engines, builders (sem I/O)
- Integração: pipeline com connectors mock + SQLite
- Fixtures em `tests/fixtures/`
- Cobertura mínima alvo: **90%**

---

## 15. Ordem de Implementação

1. Domain (entities, VOs, events, ports)
2. Application (commands, pipeline, use cases)
3. Engines (detection, scoring, correlation, dedup, enrichment)
4. Infrastructure (DI, persistence, OPSEC, observability, config)
5. Connector SDK + connectors concretos
6. Exporters + Integrations
7. CLI + Scheduler
8. Tests + Docs
9. Django prep stubs

Cada arquivo é criado com responsabilidade documentada (docstring de módulo)
antes/junto ao código.
