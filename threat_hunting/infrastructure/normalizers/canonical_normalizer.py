"""CanonicalNormalizer — normaliza campos comuns em findings e indicadores.

Aplicado após o Extract para garantir formatos consistentes antes do dedup/hash.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse, urlunparse

from ...core.domain.entities import Finding
from ...core.domain.value_objects import IndicatorType


class CanonicalNormalizer:
    """Implementa ``NormalizerPort`` — usado dentro do pipeline se necessário.

    Também atribui ``dedup_hash`` (sha256 sobre título+source+chave-normalizada).
    """

    async def normalize(self, finding: Finding) -> Finding:
        for ind in finding.indicators:
            match ind.type:
                case IndicatorType.URL:
                    ind.value = self._normalize_url(ind.value)
                case IndicatorType.DOMAIN:
                    ind.value = ind.value.lower().strip(".")
                case IndicatorType.EMAIL:
                    ind.value = ind.value.lower()
                case IndicatorType.HASH_MD5 | IndicatorType.HASH_SHA1 | IndicatorType.HASH_SHA256:
                    ind.value = ind.value.lower()
                case _:
                    pass
        finding.dedup_hash = self._compute_dedup_hash(finding)
        finding.record_event("normalize", "canonical normalization applied")
        return finding

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower() or "http"
        netloc = parsed.netloc.lower()
        return urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, ""))

    @staticmethod
    def _compute_dedup_hash(finding: Finding) -> str:
        parts = [
            finding.title.strip().lower(),
            finding.source.source.lower(),
            finding.source.url or "",
        ]
        ind_values = sorted(f"{i.type.value}:{i.value.lower()}" for i in finding.indicators)
        parts.extend(ind_values)
        return hashlib.sha256("||".join(parts).encode("utf-8")).hexdigest()
