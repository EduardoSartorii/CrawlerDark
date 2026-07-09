"""Utilidades comuns a todos os subcomandos da CLI."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from ..composition_root import CompositionRoot

T = TypeVar("T")


def run_async(coro_factory: Callable[[], Awaitable[T]]) -> T:
    return asyncio.run(coro_factory())


async def bootstrap(config_dir: str = "config", *, ensure_schema: bool = False) -> CompositionRoot:
    root = CompositionRoot(config_dir)
    if ensure_schema:
        await root.create_schema()
    return root
