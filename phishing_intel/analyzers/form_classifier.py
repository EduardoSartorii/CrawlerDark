"""Classificador de objetivo de phishing baseado em formulários.

Arquitetura
-----------
Combina regex, heurísticas e análise de campos/labels/placeholders do DOM
para inferir o(s) objetivo(s) da página de phishing.

Responsabilidade do componente
------------------------------
Mapear os formulários extraídos para uma ou mais categorias de
:class:`PhishingType`, que posteriormente viram tags MISP
``fraude:objetivo=<valor>``.

Fluxo de execução
-----------------
``classify(dom)`` -> agrega tokens de todos os campos -> aplica heurísticas
por categoria -> lista ordenada de :class:`PhishingType`.
"""

from __future__ import annotations

import re

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import DomStructure, PhishingType
from phishing_intel.utils import normalize_text

logger = get_logger(__name__)

# Sinais textuais por categoria. As chaves são termos (pt/en) que aparecem
# em nomes de campo, labels e placeholders de kits reais.
_CARD_TERMS = (
    "card",
    "cartao",
    "cartão",
    "cc",
    "cvv",
    "cvc",
    "validade",
    "expiry",
    "creditcard",
    "numero do cartao",
    "bandeira",
)
_OTP_TERMS = (
    "otp",
    "token",
    "codigo",
    "código",
    "2fa",
    "mfa",
    "sms",
    "verification",
    "verificacao",
    "verificação",
    "authcode",
    "one time",
)
_CREDENTIAL_TERMS = (
    "password",
    "senha",
    "passwd",
    "pwd",
    "login",
    "usuario",
    "usuário",
    "email",
    "user",
    "agencia",
    "conta",
)
_IDENTITY_TERMS = (
    "cpf",
    "cnpj",
    "rg",
    "nascimento",
    "birth",
    "ssn",
    "documento",
    "mae",
    "mãe",
    "endereco",
    "endereço",
    "telefone",
    "phone",
)

# Regex para detectar campos de senha explicitamente (type=password).
_PASSWORD_TYPE_RE = re.compile(r"\bpassword\b", re.IGNORECASE)


class FormClassifier:
    """Classifica o objetivo de phishing a partir da estrutura DOM."""

    def classify(self, dom: DomStructure) -> list[PhishingType]:
        """Classifica os objetivos de phishing presentes na página.

        Args:
            dom: Estrutura DOM previamente extraída.

        Returns:
            Lista ordenada e sem duplicatas de :class:`PhishingType`. Se
            houver formulários mas nenhum sinal específico, retorna
            ``GENERIC_DATA_COLLECTION``.
        """
        tokens = self._collect_tokens(dom)
        has_password = any(
            _PASSWORD_TYPE_RE.search(t)
            for form in dom.forms
            for t in form.input_types
        )

        detected: set[PhishingType] = set()

        # Card harvesting: presença de termos de cartão.
        if self._matches(tokens, _CARD_TERMS):
            detected.add(PhishingType.CARD_HARVESTING)

        # OTP harvesting: termos de código/token de uso único.
        if self._matches(tokens, _OTP_TERMS):
            detected.add(PhishingType.OTP_HARVESTING)

        # Credential harvesting: campo de senha OU termos de credencial.
        if has_password or self._matches(tokens, _CREDENTIAL_TERMS):
            detected.add(PhishingType.CREDENTIAL_HARVESTING)

        # Identity theft: dados pessoais/documentos.
        if self._matches(tokens, _IDENTITY_TERMS):
            detected.add(PhishingType.IDENTITY_THEFT)

        # Account takeover: credencial + segundo fator (OTP) na mesma página
        # sugere tomada de conta completa (regra de negócio).
        if (
            PhishingType.CREDENTIAL_HARVESTING in detected
            and PhishingType.OTP_HARVESTING in detected
        ):
            detected.add(PhishingType.ACCOUNT_TAKEOVER)

        # Fallback: existe formulário mas nenhum sinal específico casou.
        if not detected and dom.forms:
            detected.add(PhishingType.GENERIC_DATA_COLLECTION)

        result = sorted(detected, key=lambda t: t.value)
        logger.info("form_classified", types=[t.value for t in result])
        return result

    def _collect_tokens(self, dom: DomStructure) -> str:
        """Concatena e normaliza todos os textos relevantes dos formulários.

        Inclui nomes de campo, labels e placeholders — as três fontes mais
        confiáveis de intenção do formulário.
        """
        parts: list[str] = []
        for form in dom.forms:
            parts.extend(form.input_names)
            parts.extend(form.labels)
            parts.extend(form.placeholders)
            parts.extend(form.hidden_fields)
        return normalize_text(" ".join(parts))

    @staticmethod
    def _matches(tokens: str, terms: tuple[str, ...]) -> bool:
        """Retorna ``True`` se algum termo aparecer no texto agregado.

        Args:
            tokens: Texto normalizado dos campos do formulário.
            terms: Termos-sinais da categoria.
        """
        return any(term in tokens for term in terms)
