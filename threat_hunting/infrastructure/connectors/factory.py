"""ConnectorFactory — instancia conectores a partir de configuração."""

from __future__ import annotations

from ..config.schemas import ConnectorConfig, OpsecConfig
from ..opsec.opsec_http_client import OpsecHTTPClient
from .base import BaseConnector
from .registry import ConnectorRegistry


class ConnectorFactory:
    """Fábrica: recebe ``ConnectorConfig`` e devolve instância pronta.

    Usa perfil OPSEC configurado (com fallback para ``default``) para injetar
    um ``OpsecHTTPClient`` já configurado ao conector.
    """

    def __init__(self, opsec_config: OpsecConfig) -> None:
        self._opsec = opsec_config

    def build(self, config_name: str, config: ConnectorConfig) -> BaseConnector:
        connector_cls = ConnectorRegistry.get(config.type)
        profile_name = config.opsec_profile or self._opsec.default_profile
        profile = self._opsec.profiles.get(profile_name) or self._opsec.profiles.get(
            self._opsec.default_profile
        )
        if profile is None:
            raise ValueError(f"OPSEC profile not found: {profile_name}")
        http_client = OpsecHTTPClient(profile, name=f"{config_name}:{profile_name}")
        instance = connector_cls(options=dict(config.options), http=http_client)
        instance.name = config_name
        return instance
