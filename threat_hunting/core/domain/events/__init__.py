"""
Domain Events module.

Domain events are the primary mechanism for loose coupling between
bounded contexts in the CTI platform.

All domain events inherit from DomainEvent in core.domain.entities.base.
They are collected by aggregate roots and dispatched by the application layer
after a successful transaction commit.

Event flow:
    Entity accumulates events → UoW commit → EventBus dispatches → Handlers react

This module re-exports the events for convenient importing.
"""

from ..entities.base import DomainEvent
from ..entities.finding import (
    FindingConfirmedEvent,
    FindingCreatedEvent,
    FindingExportedEvent,
    FindingFalsePositiveEvent,
    FindingScoredEvent,
)
from ..entities.indicator import IndicatorAddedEvent, IndicatorWhitelistedEvent

__all__ = [
    "DomainEvent",
    "FindingCreatedEvent",
    "FindingConfirmedEvent",
    "FindingScoredEvent",
    "FindingExportedEvent",
    "FindingFalsePositiveEvent",
    "IndicatorAddedEvent",
    "IndicatorWhitelistedEvent",
]
