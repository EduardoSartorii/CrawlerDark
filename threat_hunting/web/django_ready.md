# Preparação para Django Admin

O projeto já está preparado para integração com Django sem alterações no domínio:

- Os casos de uso estão isolados em `application/use_cases.py`.
- Entidades ficam em `domain/entities.py`.
- Persistência abstraída por Repository + Unit of Work em `storage/repository.py`.
- Conectores e regras dinâmicas podem ser administrados via tabelas Django no futuro.

Modelos recomendados para painel:

- ConnectorConfig
- Watchlist
- DetectionRule
- ScoringPolicy
- SchedulerJob
- ProxyProfile
- IntegrationConfig
- UserRolePermission
- FindingRecord
- ExportAudit
- ExecutionLog
- MetricSnapshot
