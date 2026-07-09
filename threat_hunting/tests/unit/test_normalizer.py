"""Unit tests for normalizer."""

from threat_hunting.core.contracts.services import ExtractedData, ParsedData
from threat_hunting.infrastructure.normalizers.finding import FindingNormalizer


def test_normalizer():
    normalizer = FindingNormalizer()
    parsed = ParsedData(fields={"title": "Alert"}, content="admin@example.com at 1.2.3.4")
    extracted = ExtractedData(
        parsed=parsed,
        indicators=[{"type": "email", "value": "admin@example.com"}],
        entities={"emails": ["admin@example.com"]},
    )
    draft = normalizer.normalize(extracted, "test", "api")
    assert draft.title == "Alert"
    assert len(draft.indicators) == 1
    finding = draft.to_finding()
    assert finding.connector == "test"
