"""Unit tests for storage backends."""

import pytest

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.storage.backends import JsonStorageBackend


@pytest.mark.asyncio
async def test_json_storage(tmp_path):
    backend = JsonStorageBackend(str(tmp_path))
    finding = Finding(title="Stored", source=SourceType.API, connector="test")
    saved = await backend.save_finding(finding)
    assert saved.id == finding.id

    retrieved = await backend.get_finding(str(finding.id))
    assert retrieved is not None
    assert retrieved.title == "Stored"

    all_findings = await backend.list_findings()
    assert len(all_findings) == 1

    health = await backend.health()
    assert health.value == "healthy"
