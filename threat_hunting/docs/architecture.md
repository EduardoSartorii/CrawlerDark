"""Arquitetura corporativa da plataforma Threat Hunting Collection.

Este documento é a referência oficial de arquitetura para evolução da solução.
"""

# Threat Hunting Collection Platform - Arquitetura

## 1) Princípios arquiteturais

- **Clean Architecture**: regras de negócio em `domain` e `application`, detalhes em `infrastructure`.
- **DDD (Domain-Driven Design)**: o domínio é centrado no agregado `Finding` e em catálogos de inteligência (watchlists, regras, iocs).
- **Hexagonal Architecture**: portas (interfaces/contratos em `core`) e adaptadores (infraestrutura).
- **SOLID**: cada componente possui uma responsabilidade única, baixo acoplamento e alta coesão.
- **Event-Driven**: execução da pipeline publica eventos de estágio, erro, score e export.

## 2) Domínio da aplicação

### Bounded Contexts

1. **Collection Context**
   - Descoberta e execução de conectores.
   - Coleta de dados brutos por fonte.
2. **Processing Context**
   - Parser, extractor, normalizer, detecção, score, correlação, deduplicação e enriquecimento.
3. **Persistence Context**
   - Persistência abstrata com Repository + Unit of Work.
4. **Distribution Context**
   - Exportação para MISP, OpenCTI, Splunk, OpenSearch, Webhook, STIX/TAXII.
5. **Governance Context**
   - Auditoria, observabilidade, health checks e controle de conectores.

### Entidades principais

- `Finding`: entidade canônica para qualquer resultado.
- `DetectionRule`: regra dinâmica (regex, keyword, IOC, threat actor, threshold e composições).
- `ScoringPolicy`: pesos de score configuráveis.
- `WatchlistProfile`: listas monitoradas (VIP, marca, domínio, IOC, atores etc).

## 3) Contratos e portas (Core)

Os contratos residem em `core/contracts.py` e definem:

- `ConnectorPort`: `connect`, `collect`, `parse`, `normalize`, `health`, `close`.
- `PipelineStagePort`: parser/extractor/normalizer/engines.
- `RepositoryPort` e `UnitOfWorkPort`.
- `ExporterPort`.
- `EventBusPort`.
- `StoragePort`.
- `TransportPort` (camada OPSEC).

Regra crítica: **nenhum módulo de domínio/aplicação depende de biblioteca externa**.

## 4) Design Patterns aplicados

- **Repository Pattern**: abstração de persistência de Findings.
- **Unit of Work**: controle transacional em lote por execução.
- **Dependency Injection**: container central em `application/container.py`.
- **Strategy Pattern**: estratégias de score por tipo de evidência.
- **Factory Pattern**: criação dinâmica de conectores/exportadores.
- **Builder Pattern**: construção segura de `Finding`.
- **Adapter Pattern**: integração MISP/OpenCTI/Splunk/REST.
- **Command Pattern**: comandos de execução via CLI (`hunt run`, `hunt export`, etc.).
- **Observer Pattern**: subscribers de eventos para logging e métricas.
- **Plugin Pattern**: descoberta automática de conectores sem alterar o core.

## 5) Estrutura completa do projeto

```text
threat_hunting/
  core/              # contratos, eventos e tipos compartilhados do núcleo
  domain/            # entidades, value objects e regras de domínio
  application/       # casos de uso, comandos, handlers, factories e container DI
  infrastructure/    # adaptadores técnicos (db, opsec, conectores concretos)
  connectors/        # SDK de conectores e conectores plugináveis
  parsers/
  extractors/
  normalizers/
  detections/
  scoring/
  correlation/
  deduplication/
  enrichment/
  pipelines/
  scheduler/
  plugins/
  storage/
  exporters/
  integrations/
  cli/
  api/
  web/
  database/
  tests/
  config/
  docs/
```

## 6) Fluxo completo da aplicação

### Fluxo principal

1. CLI recebe comando (`hunt run reddit`).
2. Command Handler resolve conector via Factory/Plugin Manager.
3. Conector executa `connect` + `collect`.
4. Dados passam por pipeline:
   - Parser
   - Extractor
   - Normalizer
   - Detection Engine
   - Scoring Engine
   - Correlation Engine
   - Deduplication Engine
   - Enrichment Engine
   - Persistence
   - Export
5. Cada estágio publica evento no Event Bus.
6. Observers registram logs estruturados e métricas.
7. Se score > threshold, Exporter MISP pode ser acionado automaticamente.

### Fluxo de scheduler

1. APScheduler dispara job.
2. Job chama o mesmo command handler da CLI (sem duplicar lógica).
3. Execução idempotente com UoW e deduplicação por fingerprint.

## 7) OPSEC (camada independente)

- OPSEC fica em `infrastructure/opsec`.
- Suporta:
  - proxies HTTP/HTTPS
  - proxies SOCKS5
  - perfis por conector
  - user-agent por perfil
  - retries/backoff/rate-limit
  - credenciais via variáveis de ambiente
- Conector **nunca** instancia `httpx` diretamente; usa `TransportPort`.

## 8) Modelo canônico Finding

O modelo `Finding` contém exatamente:

- `id`
- `title`
- `description`
- `source`
- `connector`
- `category`
- `severity`
- `score`
- `confidence`
- `created_at`
- `updated_at`
- `raw_data`
- `normalized_data`
- `metadata`
- `tags`
- `artifacts`
- `indicators`
- `relationships`
- `timeline`

## 9) Regras dinâmicas

- Nenhuma regra hardcoded.
- Regras carregadas de YAML em `config/`.
- Tipos suportados:
  - regex
  - yara (placeholder para engine externa)
  - sigma (contextual)
  - keyword
  - IOC match
  - threat actor match
  - whitelist/blacklist
  - threshold
  - regras compostas

## 10) Preparação para Django

Embora a entrega inicial seja CLI + Scheduler:

- Casos de uso já são independentes da interface.
- Entidades e serviços podem ser usados por uma camada `web/django`.
- Módulos de administração mapeados:
  - conectores, watchlists, regras, scheduler, proxies, integrações, usuários/permissões, findings, exportações, logs e métricas.

## 11) Responsabilidade de cada módulo (resumo)

- `core`: contratos e eventos.
- `domain`: linguagem de negócio CTI.
- `application`: orquestração de casos de uso.
- `infrastructure`: tecnologia concreta.
- `connectors`: SDK + conectores plugin.
- `pipelines`: orquestração de estágios.
- `scheduler`: execução recorrente.
- `storage`: adaptadores de backend.
- `exporters`: envio de inteligência.
- `integrations`: adapters externos.
- `cli`: interface operacional.
- `tests`: validação unitária e integração.
