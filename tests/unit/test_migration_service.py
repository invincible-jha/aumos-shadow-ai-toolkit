"""Unit tests for MigrationProposalService.

Covers:
  - SHADOW_TO_AUMOS_MAPPING completeness (10+ mappings)
  - generate_proposal — correct module selection for each indicator
  - estimate_total_migration — aggregate hours, complexity breakdown, module breakdown
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from aumos_shadow_ai_toolkit.core.models.shadow_detection import ShadowAIDetection
from aumos_shadow_ai_toolkit.core.services.migration_service import (
    SHADOW_TO_AUMOS_MAPPING,
    MigrationProposalService,
)

_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_NOW = datetime.now(tz=timezone.utc)


def _make_detection(
    business_value_indicator: str = "text-generation",
    provider: str = "openai",
) -> ShadowAIDetection:
    """Create a minimal ShadowAIDetection for testing."""
    detection = ShadowAIDetection.__new__(ShadowAIDetection)
    detection.id = uuid.uuid4()
    detection.tenant_id = _TENANT_ID
    detection.source_ip = "10.0.0.1"
    detection.destination_domain = "api.openai.com"
    detection.provider = provider
    detection.estimated_data_sensitivity = "medium"
    detection.estimated_daily_cost_usd = Decimal("0.01")
    detection.compliance_risk_score = Decimal("45.00")
    detection.business_value_indicator = business_value_indicator
    detection.status = "detected"
    detection.created_at = _NOW
    detection.updated_at = _NOW
    return detection


@pytest.fixture
def service() -> MigrationProposalService:
    """MigrationProposalService instance for testing."""
    return MigrationProposalService()


class TestMappingCoverage:
    """Verify the mapping registry is sufficiently populated."""

    def test_at_least_10_mappings_registered(self) -> None:
        """SHADOW_TO_AUMOS_MAPPING must contain at least 10 entries."""
        assert len(SHADOW_TO_AUMOS_MAPPING) >= 10, (
            f"Expected >= 10 mappings, found {len(SHADOW_TO_AUMOS_MAPPING)}"
        )

    def test_unknown_mapping_present(self) -> None:
        """Fallback 'unknown' mapping must always be present."""
        assert "unknown" in SHADOW_TO_AUMOS_MAPPING

    @pytest.mark.parametrize(
        "indicator",
        [
            "code-assist",
            "text-generation",
            "data-analysis",
            "image-generation",
            "productivity",
            "audio",
            "embedding",
            "fine-tuning",
            "document-processing",
            "search",
            "summarisation",
            "translation",
            "classification",
        ],
    )
    def test_indicator_mapped(self, indicator: str) -> None:
        """All expected business value indicators must have explicit mappings."""
        assert indicator in SHADOW_TO_AUMOS_MAPPING, (
            f"Indicator '{indicator}' is not mapped"
        )

    def test_all_mappings_have_required_fields(self) -> None:
        """Every mapping must include module, complexity, hours, preservation_pct, description."""
        required_fields = {"module", "complexity", "hours", "preservation_pct", "description"}
        for indicator, mapping in SHADOW_TO_AUMOS_MAPPING.items():
            missing = required_fields - set(mapping.keys())
            assert not missing, (
                f"Mapping '{indicator}' is missing fields: {missing}"
            )

    def test_all_complexities_are_valid(self) -> None:
        """Every mapping must use a valid complexity tier."""
        valid_complexities = {"trivial", "moderate", "complex"}
        for indicator, mapping in SHADOW_TO_AUMOS_MAPPING.items():
            assert mapping["complexity"] in valid_complexities, (
                f"Mapping '{indicator}' has invalid complexity '{mapping['complexity']}'"
            )

    def test_all_preservation_pcts_in_range(self) -> None:
        """Productivity preservation percentages must be between 0 and 100."""
        for indicator, mapping in SHADOW_TO_AUMOS_MAPPING.items():
            pct = float(mapping["preservation_pct"])
            assert 0.0 <= pct <= 100.0, (
                f"Mapping '{indicator}' has preservation_pct {pct} out of range"
            )

    def test_all_hours_positive(self) -> None:
        """Estimated migration hours must be positive."""
        for indicator, mapping in SHADOW_TO_AUMOS_MAPPING.items():
            hours = float(mapping["hours"])
            assert hours > 0, (
                f"Mapping '{indicator}' has non-positive hours {hours}"
            )


class TestGenerateProposal:
    """Tests for proposal generation from a single detection."""

    @pytest.mark.asyncio
    async def test_code_assist_maps_to_llm_serving(
        self, service: MigrationProposalService
    ) -> None:
        """code-assist indicator maps to aumos-llm-serving."""
        detection = _make_detection("code-assist")
        proposal = await service.generate_proposal(detection)
        assert proposal.proposed_aumos_module == "aumos-llm-serving"
        assert proposal.migration_complexity == "trivial"

    @pytest.mark.asyncio
    async def test_text_generation_maps_to_text_engine(
        self, service: MigrationProposalService
    ) -> None:
        """text-generation indicator maps to aumos-text-engine."""
        detection = _make_detection("text-generation")
        proposal = await service.generate_proposal(detection)
        assert proposal.proposed_aumos_module == "aumos-text-engine"

    @pytest.mark.asyncio
    async def test_data_analysis_maps_to_context_graph(
        self, service: MigrationProposalService
    ) -> None:
        """data-analysis indicator maps to aumos-context-graph."""
        detection = _make_detection("data-analysis")
        proposal = await service.generate_proposal(detection)
        assert proposal.proposed_aumos_module == "aumos-context-graph"

    @pytest.mark.asyncio
    async def test_image_generation_maps_to_image_engine(
        self, service: MigrationProposalService
    ) -> None:
        """image-generation indicator maps to aumos-image-engine."""
        detection = _make_detection("image-generation")
        proposal = await service.generate_proposal(detection)
        assert proposal.proposed_aumos_module == "aumos-image-engine"

    @pytest.mark.asyncio
    async def test_unknown_indicator_uses_fallback(
        self, service: MigrationProposalService
    ) -> None:
        """Unknown business value indicator uses the 'unknown' fallback mapping."""
        detection = _make_detection("completely-unknown-indicator")
        proposal = await service.generate_proposal(detection)
        assert proposal.proposed_aumos_module == SHADOW_TO_AUMOS_MAPPING["unknown"]["module"]

    @pytest.mark.asyncio
    async def test_proposal_has_correct_detection_id(
        self, service: MigrationProposalService
    ) -> None:
        """Generated proposal references the correct detection ID."""
        detection = _make_detection("productivity")
        proposal = await service.generate_proposal(detection)
        assert proposal.detection_id == detection.id

    @pytest.mark.asyncio
    async def test_proposal_has_correct_tenant_id(
        self, service: MigrationProposalService
    ) -> None:
        """Generated proposal carries the detection's tenant ID."""
        detection = _make_detection("text-generation")
        proposal = await service.generate_proposal(detection)
        assert proposal.tenant_id == _TENANT_ID

    @pytest.mark.asyncio
    async def test_proposal_description_is_non_empty(
        self, service: MigrationProposalService
    ) -> None:
        """All proposals must include a non-empty compliance gain description."""
        for indicator in SHADOW_TO_AUMOS_MAPPING:
            detection = _make_detection(indicator)
            proposal = await service.generate_proposal(detection)
            assert proposal.compliance_gain_description, (
                f"Empty description for indicator '{indicator}'"
            )


class TestEstimateTotalMigration:
    """Tests for aggregate migration effort estimation."""

    @pytest.mark.asyncio
    async def test_empty_detections_produces_zero_summary(
        self, service: MigrationProposalService
    ) -> None:
        """Empty detection list produces a zero-value summary."""
        summary = await service.estimate_total_migration([])
        assert summary.total_detections == 0
        assert summary.total_estimated_hours == Decimal("0.0")
        assert summary.proposals == []

    @pytest.mark.asyncio
    async def test_total_hours_accumulates(self, service: MigrationProposalService) -> None:
        """Total hours is sum of all individual proposal hours."""
        detections = [
            _make_detection("code-assist"),    # 2.0 hours
            _make_detection("text-generation"), # 8.0 hours
        ]
        summary = await service.estimate_total_migration(detections)
        expected = Decimal("2.0") + Decimal("8.0")
        assert summary.total_estimated_hours == expected

    @pytest.mark.asyncio
    async def test_complexity_breakdown_correct(
        self, service: MigrationProposalService
    ) -> None:
        """Complexity breakdown counts reflect the generated proposals."""
        detections = [
            _make_detection("code-assist"),    # trivial
            _make_detection("text-generation"), # moderate
            _make_detection("fine-tuning"),    # complex
        ]
        summary = await service.estimate_total_migration(detections)
        assert summary.complexity_breakdown["trivial"] == 1
        assert summary.complexity_breakdown["moderate"] == 1
        assert summary.complexity_breakdown["complex"] == 1

    @pytest.mark.asyncio
    async def test_module_breakdown_correct(
        self, service: MigrationProposalService
    ) -> None:
        """Module breakdown counts reflect the target modules of proposals."""
        detections = [
            _make_detection("code-assist"),    # aumos-llm-serving
            _make_detection("productivity"),   # aumos-llm-serving
            _make_detection("text-generation"), # aumos-text-engine
        ]
        summary = await service.estimate_total_migration(detections)
        assert summary.module_breakdown.get("aumos-llm-serving", 0) == 2
        assert summary.module_breakdown.get("aumos-text-engine", 0) == 1

    @pytest.mark.asyncio
    async def test_proposal_count_matches_detection_count(
        self, service: MigrationProposalService
    ) -> None:
        """One proposal is generated per detection."""
        detections = [_make_detection(ind) for ind in ("code-assist", "data-analysis", "audio")]
        summary = await service.estimate_total_migration(detections)
        assert len(summary.proposals) == 3
        assert summary.total_detections == 3

    @pytest.mark.asyncio
    async def test_average_preservation_pct_computed(
        self, service: MigrationProposalService
    ) -> None:
        """Average preservation percentage is the mean of individual values."""
        detections = [
            _make_detection("code-assist"),    # 95%
            _make_detection("data-analysis"),  # 85%
        ]
        summary = await service.estimate_total_migration(detections)
        expected = round((Decimal("95.00") + Decimal("85.00")) / 2, 2)
        assert summary.average_preservation_pct == expected
