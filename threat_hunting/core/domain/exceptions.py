"""Domain exceptions.

Todas as regras de negócio violadas se propagam através destas exceções.
Infra e presentation devem tratá-las próximas às fronteiras.
"""

from __future__ import annotations


class DomainError(Exception):
    """Base para todos os erros de domínio."""


class InvalidFindingError(DomainError):
    """Estado inválido para um ``Finding``."""


class InvalidIndicatorError(DomainError):
    """Estado inválido para um ``Indicator``."""


class InvalidRuleError(DomainError):
    """Configuração de regra inválida."""


class DuplicateFindingError(DomainError):
    """Tentativa de persistir finding já existente (identidade colidente)."""


class ConnectorError(DomainError):
    """Erro genérico originado por um conector."""


class ConnectorNotFoundError(ConnectorError):
    """Conector não registrado."""


class ExporterError(DomainError):
    """Erro em exportação."""


class ScoringError(DomainError):
    """Erro no motor de score."""


class CorrelationError(DomainError):
    """Erro no motor de correlação."""


class PipelineError(DomainError):
    """Erro em uma etapa do pipeline."""

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.raw_message = message
