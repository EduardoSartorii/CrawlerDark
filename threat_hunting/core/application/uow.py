"""Re-export do ``UnitOfWorkPort`` para uso pelos casos de uso.

Não fornecemos implementação aqui — apenas re-exportamos o contrato de domínio
para conveniência do time de aplicação (evita `from ...domain.ports import`).
"""

from ..domain.ports import UnitOfWorkPort

__all__ = ["UnitOfWorkPort"]
