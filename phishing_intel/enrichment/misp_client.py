"""Cliente de integração com o MISP (PyMISP).

Arquitetura
-----------
Encapsula o PyMISP para materializar um :class:`MispEventPayload` como um
evento MISP real: cria o evento, adiciona atributos, objetos (incluindo o
objeto customizado ``phishing-campaign``) e aplica as tags locais.

Responsabilidade do componente
------------------------------
Ser a única fronteira de comunicação com o MISP. Toda a modelagem do evento
é feita antes (no :class:`CampaignBuilder`); aqui apenas materializamos.

Fluxo de execução
-----------------
``push_event(payload)`` -> monta ``MISPEvent`` -> adiciona atributos/objetos/
tags -> ``add_event`` -> retorna ``(event_id, event_uuid)``.

Observação de resiliência: se o MISP estiver desabilitado ou o PyMISP não
estiver disponível, o cliente opera em modo "no-op" e o pipeline continua.
"""

from __future__ import annotations

from typing import Any

from phishing_intel.config.settings import MISPConfig
from phishing_intel.enrichment.campaign_builder import MispEventPayload
from phishing_intel.logging_config import get_logger

logger = get_logger(__name__)


class MispClient:
    """Materializa eventos de campanha no MISP via PyMISP."""

    def __init__(
        self, config: MISPConfig | None = None, connection: Any | None = None
    ) -> None:
        """Inicializa o cliente MISP.

        Args:
            config: Configuração do MISP. Se ``None``, usa padrões (desabilitado).
            connection: Conexão PyMISP já construída (injeção para testes).
                Se ``None`` e o MISP estiver habilitado, uma conexão é criada.
        """
        self.config = config or MISPConfig()
        self._misp = connection
        # Só tenta conectar se habilitado e sem conexão injetada.
        if self._misp is None and self.config.enabled:
            self._misp = self._connect()

    @property
    def available(self) -> bool:
        """Indica se o cliente pode efetivamente enviar dados ao MISP."""
        return self._misp is not None

    def _connect(self) -> Any | None:
        """Cria a conexão PyMISP a partir da configuração.

        Returns:
            Uma instância ``PyMISP`` conectada, ou ``None`` em caso de falha
            (ou de PyMISP indisponível) — degradação graciosa.
        """
        try:
            from pymisp import PyMISP  # import local (opcional)

            client = PyMISP(
                url=self.config.url,
                key=self.config.key,
                ssl=self.config.verify_ssl,
            )
            logger.info("misp_connected", url=self.config.url)
            return client
        except Exception as exc:
            logger.error("misp_connection_failed", error=str(exc))
            return None

    def push_event(self, payload: MispEventPayload) -> tuple[str, str]:
        """Cria um evento MISP a partir do payload declarativo.

        Args:
            payload: Descrição do evento (info, atributos, objetos, tags).

        Returns:
            Tupla ``(event_id, event_uuid)``. Em modo no-op (MISP indisponível),
            retorna ``("", "")``.
        """
        if not self.available:
            logger.warning("misp_push_skipped", reason="misp_unavailable")
            return "", ""

        event = self._build_event(payload)
        try:
            result = self._misp.add_event(event, pythonify=True)
        except Exception as exc:  # pragma: no cover - depende de rede
            logger.error("misp_add_event_failed", error=str(exc))
            return "", ""

        event_id = str(getattr(result, "id", "") or "")
        event_uuid = str(getattr(result, "uuid", "") or "")
        logger.info(
            "misp_event_created",
            event_id=event_id,
            event_uuid=event_uuid,
            attributes=len(payload.attributes),
            objects=len(payload.objects),
        )
        return event_id, event_uuid

    def _build_event(self, payload: MispEventPayload) -> Any:
        """Constrói o objeto ``MISPEvent`` a partir do payload.

        A importação de PyMISP é local para permitir que o módulo seja
        importado mesmo sem a biblioteca (ambientes de análise offline).

        Args:
            payload: Descrição declarativa do evento.

        Returns:
            Uma instância ``MISPEvent`` populada.
        """
        from pymisp import MISPEvent, MISPObject

        event = MISPEvent()
        event.info = payload.info
        event.distribution = self.config.distribution
        event.threat_level_id = self.config.threat_level_id
        event.analysis = self.config.analysis

        # Atributos simples.
        for attr in payload.attributes:
            event.add_attribute(
                attr["type"],
                attr["value"],
                category=attr.get("category"),
                comment=attr.get("comment", ""),
            )

        # Objetos (x509, phishing-campaign customizado).
        for obj in payload.objects:
            # ``strict=False`` permite objetos customizados sem template
            # instalado (ex.: ``phishing-campaign``).
            misp_object = MISPObject(obj["name"], strict=False)
            is_custom = obj.get("custom", False)
            for relation, value in obj["attributes"].items():
                if value in (None, ""):
                    continue
                if is_custom:
                    # Sem template, o tipo do atributo precisa ser explícito.
                    misp_object.add_attribute(relation, value=value, type="text")
                else:
                    misp_object.add_attribute(relation, value=value)
            event.add_object(misp_object)

        # Tags locais ``fraude:*``.
        for tag in payload.tags:
            event.add_tag(tag)

        return event
