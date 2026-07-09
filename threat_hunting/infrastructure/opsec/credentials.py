"""Resolução de credenciais via variáveis de ambiente (adapter simples).

Implementa ``CredentialsPort``. Para vaults externos basta criar novo adapter
mantendo a mesma interface.
"""

from __future__ import annotations

import os


class EnvCredentials:
    """Adapter que resolve segredos a partir de ``os.environ``."""

    def get(self, key: str, default: str | None = None) -> str | None:
        return os.environ.get(key, default)

    def require(self, key: str) -> str:
        value = os.environ.get(key)
        if value is None or value == "":
            raise KeyError(f"Missing required credential: {key}")
        return value
