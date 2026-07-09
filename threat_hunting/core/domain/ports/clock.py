"""ClockPort — abstração de tempo para testabilidade determinística."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class ClockPort(Protocol):
    def now(self) -> datetime: ...
