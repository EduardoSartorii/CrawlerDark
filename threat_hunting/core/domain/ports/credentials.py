"""CredentialsPort — resolução de segredos (env, vault, k8s secret, ...)."""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CredentialsPort(Protocol):
    def get(self, key: str, default: str | None = None) -> str | None: ...

    def require(self, key: str) -> str: ...
