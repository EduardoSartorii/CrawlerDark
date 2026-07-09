"""Classificador do tipo de objetivo de phishing (form_classifier).

Responsabilidade do componente
-------------------------------
Classificar automaticamente o objetivo de uma pagina de phishing
(``PhishingType``) com base nos campos de formulario extraidos pelo
``dom_analyzer``: nomes, IDs, tipos de input, labels e placeholders.

Fluxo de execucao
------------------
1. Cada campo de cada formulario e reduzido a um "texto de sinal" (name +
   id + label + placeholder + type), normalizado para minusculas sem
   acentos.
2. Cada categoria de phishing possui um conjunto de padroes regex; o numero
   de campos que casam com cada categoria determina sua pontuacao bruta.
3. A categoria com maior pontuacao "vence"; a ordem de prioridade
   (``_PRIORITY_ORDER``) resolve empates favorecendo os objetivos mais
   criticos/especificos (ex.: OTP > Cartao > Identidade > Account Takeover
   > Credential Harvesting), pois exigem resposta de triagem mais rapida.

Regra de negocio
----------------
Uma pagina e classificada como ``GENERIC_DATA_COLLECTION`` quando possui
formularios com campos de dados pessoais mas nenhum sinal especifico o
suficiente para as categorias acima, e ``UNKNOWN`` quando nao ha formularios
ou nenhum campo reconhecivel — nesse caso, a decisao de triagem manual cabe
ao analista humano.
"""

from __future__ import annotations

import re
import unicodedata

from models.findings import ClassificationResult, DomFinding, FormFieldFinding, PhishingType

# Ordem de prioridade para resolucao de empates: categorias mais criticas ou
# mais especificas tem prioridade sobre categorias mais genericas.
_PRIORITY_ORDER = [
    PhishingType.OTP_HARVESTING,
    PhishingType.CARD_HARVESTING,
    PhishingType.IDENTITY_THEFT,
    PhishingType.ACCOUNT_TAKEOVER,
    PhishingType.CREDENTIAL_HARVESTING,
    PhishingType.GENERIC_DATA_COLLECTION,
]

_PATTERNS: dict[PhishingType, list[re.Pattern[str]]] = {
    PhishingType.OTP_HARVESTING: [
        re.compile(r"\botp\b"),
        re.compile(r"\bcodigo\b.*(verificacao|seguranca|sms|token)"),
        re.compile(r"\bverification[_\s-]?code\b"),
        re.compile(r"\bpin\b"),
        re.compile(r"\btoken\b"),
        re.compile(r"\b2fa\b"),
        re.compile(r"\bmfa\b"),
    ],
    PhishingType.CARD_HARVESTING: [
        re.compile(r"\bcard[_\s-]?number\b"),
        re.compile(r"\bnumero.*cart[aã]o\b"),
        re.compile(r"\bcvv\b"),
        re.compile(r"\bcvc\b"),
        re.compile(r"\bexpir(y|acao|ation)\b"),
        re.compile(r"\bvalidade\b"),
        re.compile(r"\bcard[_\s-]?holder\b"),
        re.compile(r"\btitular\b"),
        re.compile(r"\bcredit[_\s-]?card\b"),
    ],
    PhishingType.IDENTITY_THEFT: [
        re.compile(r"\bcpf\b"),
        re.compile(r"\brg\b"),
        re.compile(r"\bssn\b"),
        re.compile(r"\bsocial[_\s-]?security\b"),
        re.compile(r"\bdocument(o|_id)?\b"),
        re.compile(r"\bdata.*nascimento\b"),
        re.compile(r"\bbirth[_\s-]?date\b"),
        re.compile(r"\bmae\b"),
        re.compile(r"\bmother.*maiden\b"),
    ],
    PhishingType.ACCOUNT_TAKEOVER: [
        re.compile(r"\bsecurity[_\s-]?question\b"),
        re.compile(r"\bpergunta.*seguranca\b"),
        re.compile(r"\brecovery[_\s-]?email\b"),
        re.compile(r"\brecuperacao\b"),
        re.compile(r"\bsession\b"),
        re.compile(r"\bdevice[_\s-]?id\b"),
    ],
    PhishingType.CREDENTIAL_HARVESTING: [
        re.compile(r"\b(user(name)?|login|e-?mail)\b"),
        re.compile(r"\bpass(word)?\b"),
        re.compile(r"\bsenha\b"),
    ],
    PhishingType.GENERIC_DATA_COLLECTION: [
        re.compile(r"\bnome\b"),
        re.compile(r"\bname\b"),
        re.compile(r"\btelefone\b"),
        re.compile(r"\bphone\b"),
        re.compile(r"\bendereco\b"),
        re.compile(r"\baddress\b"),
    ],
}


def _strip_accents(text: str) -> str:
    """Remove acentuacao para tornar as regex resilientes a texto em pt-BR."""
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(char for char in normalized if not unicodedata.combining(char))


def _field_signal_text(field: FormFieldFinding) -> str:
    """Concatena todos os atributos textuais relevantes de um campo em um unico texto normalizado."""
    parts = [field.name or "", field.field_id or "", field.label or "", field.placeholder or "", field.field_type]
    return _strip_accents(" ".join(parts).lower())


def classify_phishing_type(dom: DomFinding) -> ClassificationResult:
    """Classifica o objetivo de phishing predominante de uma pagina.

    Args:
        dom: Resultado da analise de DOM contendo os formularios extraidos.

    Returns:
        :class:`ClassificationResult` com o tipo mais provavel, a confianca
        estimada (proporcao de campos que corroboram a categoria vencedora)
        e os sinais textuais que motivaram a decisao.
    """
    all_fields = [field for form in dom.forms for field in form.fields]
    if not all_fields:
        return ClassificationResult(phishing_type=PhishingType.UNKNOWN, confidence=0.0, matched_signals=[])

    scores: dict[PhishingType, int] = {ptype: 0 for ptype in _PATTERNS}
    matched_signals: dict[PhishingType, list[str]] = {ptype: [] for ptype in _PATTERNS}

    for field in all_fields:
        signal_text = _field_signal_text(field)
        if not signal_text.strip():
            continue
        for phishing_type, patterns in _PATTERNS.items():
            for pattern in patterns:
                if pattern.search(signal_text):
                    scores[phishing_type] += 1
                    matched_signals[phishing_type].append(f"{field.name or field.field_id or '?'}:{pattern.pattern}")
                    break

    best_type = PhishingType.UNKNOWN
    best_score = 0
    for phishing_type in _PRIORITY_ORDER:
        if scores[phishing_type] > best_score:
            best_score = scores[phishing_type]
            best_type = phishing_type

    if best_score == 0:
        return ClassificationResult(phishing_type=PhishingType.UNKNOWN, confidence=0.0, matched_signals=[])

    confidence = min(1.0, best_score / len(all_fields))
    return ClassificationResult(
        phishing_type=best_type,
        confidence=round(confidence, 2),
        matched_signals=matched_signals[best_type],
    )
