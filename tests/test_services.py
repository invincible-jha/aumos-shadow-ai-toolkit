"""Unit tests for the Shadow AI Toolkit core services.

Tests cover DiscoveryService, RiskAssessorService, and MigrationService
with all external dependencies mocked via fixtures from conftest.py.
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from aumos_common.errors import ConflictError, NotFoundError

from aumos_shadow_ai_toolkit.core.services import (
    DiscoveryService,
    MigrationService,
    RiskAssessorService,
    _compute_risk_level,
)
from tests.conftest import make_discovery, make_migration_plan, make_scan_result


# ---------------------------------------------------------------------------
# _compute_risk_level tests
# ---------------------------------------------------------------------------


class TestComputeRiskLevel:
    """Tests for the risk level computation helper."""

    def test_critical_at_threshold(self) -> None:
        """Score at the critical threshold is rated critical."""
        assert _compute_risk_level(0.7, 0.7, 0.5, 0.3) == "critical"

    def test_critical_above_threshold(self) -> None:
        """Score above the critical threshold is rated critical."""
        assert _compute_risk_level(0.95, 0.7, 0.5, 0.3) == "critical"

    def test_high_between_thresholds(self) -> None:
        """Score between high and critical thresholds is rated high."""
        assert _compute_risk_level(0.6, 0.7, 0.5, 0.3) == "high"

    def test_medium_between_thresholds(self) -> None:
        """Score between medium and high thresholds is rated medium."""
        assert _compute_risk_level(0.4, 0.7, 0.5, 0.3) == "medium"

    def test_low_below_medium_threshold(self) -> None:
        """Score below the medium threshold is rated low."""
        assert _compute_risk_level(0.1, 0.7, 0.5, 0.3) == "low"

    def test_zero_score_is_low(self) -> None:
        """A zero risk score is rated low."""
        assert _compute_risk_level(0.0, 0.7, 0.5, 0.3) == "low"

    def test_maximum_score_is_critical(self) -> None:
        """A maximum risk score of 1.0 is rated critical."""
        assert _compute_risk_level(1.0, 0.7, 0.5, 0.3) == "critical"


# ---------------------------------------------------------------------------
# DiscoveryService tests
# ---------------------------------------------------------------------------


class TestDiscoveryService:
    """Tests for DiscoveryService."""

    @pytest.mark.asyncio
    async def test_initiate_scan_no_detections(
        self,
        discovery_service: DiscoveryService,
        mock_scan_repo: object,
        mock_scanner: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Scan with no detections produces a completed scan with zero discoveries."""
        scan = make_scan_result(tenant_id=tenant_id)
        mock_scan_repo.create = AsyncMock(return_value=scan)  # type: ignore[attr-defined]
        mock_scan_repo.complete = AsyncMock(return_value=scan)  # type: ignore[attr-defined]
        mock_scanner.scan = AsyncMock(return_value=[])  # type: ignore[attr-defined]

        result = await discovery_service.initiate_scan(tenant_id=tenant_id)

        assert result.id == scan.id
        mock_scan_repo.complete.assert_awaited_once()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_initiate_scan_new_detection_creates_discovery(
        self,
        discovery_service: DiscoveryService,
        mock_scan_repo: object,
        mock_scanner: object,
        mock_discovery_repo: object,
        mock_publisher: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """New detection creates a discovery record and publishes event."""
        scan = make_scan_result(tenant_id=tenant_id)
        discovery = make_discovery(tenant_id=tenant_id)

        mock_scan_repo.create = AsyncMock(return_value=scan)  # type: ignore[attr-defined]
        mock_scan_repo.complete = AsyncMock(return_value=scan)  # type: ignore[attr-defined]
        mock_scanner.scan = AsyncMock(  # type: ignore[attr-defined]
            return_value=[
                {
                    "tool_name": "ChatGPT / OpenAI API",
                    "api_endpoint": "api.openai.com",
                    "detection_method": "dns_pattern",
                    "detected_user_id": None,
                    "request_count": 1,
                    "estimated_volume_kb": 0,
                }
            ]
        )
        mock_discovery_repo.find_existing = AsyncMock(return_value=None)  # type: ignore[attr-defined]
        mock_discovery_repo.create = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]

        result = await discovery_service.initiate_scan(tenant_id=tenant_id)

        mock_discovery_repo.create.assert_awaited_once()  # type: ignore[attr-defined]
        mock_publisher.publish.assert_awaited_once()  # type: ignore[attr-defined]
        assert result.id == scan.id

    @pytest.mark.asyncio
    async def test_initiate_scan_redetection_increments_counter(
        self,
        discovery_service: DiscoveryService,
        mock_scan_repo: object,
        mock_scanner: object,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Re-detection of existing discovery increments counters, not creates new."""
        scan = make_scan_result(tenant_id=tenant_id)
        existing = make_discovery(tenant_id=tenant_id, status="assessed")

        mock_scan_repo.create = AsyncMock(return_value=scan)  # type: ignore[attr-defined]
        mock_scan_repo.complete = AsyncMock(return_value=scan)  # type: ignore[attr-defined]
        mock_scanner.scan = AsyncMock(  # type: ignore[attr-defined]
            return_value=[
                {
                    "tool_name": existing.tool_name,
                    "api_endpoint": existing.api_endpoint,
                    "detection_method": "dns_pattern",
                    "detected_user_id": None,
                    "request_count": 5,
                    "estimated_volume_kb": 100,
                }
            ]
        )
        mock_discovery_repo.find_existing = AsyncMock(return_value=existing)  # type: ignore[attr-defined]
        mock_discovery_repo.increment_request_count = AsyncMock(return_value=existing)  # type: ignore[attr-defined]
        mock_discovery_repo.create = AsyncMock()  # type: ignore[attr-defined]

        await discovery_service.initiate_scan(tenant_id=tenant_id)

        mock_discovery_repo.increment_request_count.assert_awaited_once()  # type: ignore[attr-defined]
        mock_discovery_repo.create.assert_not_awaited()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_get_discovery_not_found_raises(
        self,
        discovery_service: DiscoveryService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Getting a non-existent discovery raises NotFoundError."""
        mock_discovery_repo.get_by_id = AsyncMock(return_value=None)  # type: ignore[attr-defined]

        with pytest.raises(NotFoundError):
            await discovery_service.get_discovery(uuid.uuid4(), tenant_id)

    @pytest.mark.asyncio
    async def test_dismiss_discovery_success(
        self,
        discovery_service: DiscoveryService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Dismissing a non-terminal discovery succeeds."""
        discovery = make_discovery(tenant_id=tenant_id, status="assessed")
        dismissed = make_discovery(
            discovery_id=discovery.id, tenant_id=tenant_id, status="dismissed"
        )
        mock_discovery_repo.get_by_id = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]
        mock_discovery_repo.update_status = AsyncMock(return_value=dismissed)  # type: ignore[attr-defined]

        result = await discovery_service.dismiss_discovery(discovery.id, tenant_id, "False positive")

        assert result.status == "dismissed"
        mock_discovery_repo.update_status.assert_awaited_once_with(  # type: ignore[attr-defined]
            discovery_id=discovery.id,
            status="dismissed",
            dismissed_reason="False positive",
        )

    @pytest.mark.asyncio
    async def test_dismiss_terminal_discovery_raises_conflict(
        self,
        discovery_service: DiscoveryService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Dismissing an already-dismissed discovery raises ConflictError."""
        discovery = make_discovery(tenant_id=tenant_id, status="dismissed")
        mock_discovery_repo.get_by_id = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]

        with pytest.raises(ConflictError):
            await discovery_service.dismiss_discovery(discovery.id, tenant_id)


# ---------------------------------------------------------------------------
# RiskAssessorService tests
# ---------------------------------------------------------------------------


class TestRiskAssessorService:
    """Tests for RiskAssessorService."""

    @pytest.mark.asyncio
    async def test_assess_discovery_persists_risk_score(
        self,
        risk_service: RiskAssessorService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Assessing a discovery persists the risk score from the governance adapter."""
        discovery = make_discovery(tenant_id=tenant_id, status="detected")
        assessed = make_discovery(
            discovery_id=discovery.id, tenant_id=tenant_id,
            status="assessed", risk_score=0.75, risk_level="critical"
        )
        mock_discovery_repo.get_by_id = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]
        mock_discovery_repo.update_risk_assessment = AsyncMock(return_value=assessed)  # type: ignore[attr-defined]
        mock_discovery_repo.update_status = AsyncMock(return_value=assessed)  # type: ignore[attr-defined]

        result = await risk_service.assess_discovery(discovery.id, tenant_id)

        mock_discovery_repo.update_risk_assessment.assert_awaited_once()  # type: ignore[attr-defined]
        assert result.status == "assessed"

    @pytest.mark.asyncio
    async def test_assess_discovery_not_found_raises(
        self,
        risk_service: RiskAssessorService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Assessing a non-existent discovery raises NotFoundError."""
        mock_discovery_repo.get_by_id = AsyncMock(return_value=None)  # type: ignore[attr-defined]

        with pytest.raises(NotFoundError):
            await risk_service.assess_discovery(uuid.uuid4(), tenant_id)

    @pytest.mark.asyncio
    async def test_get_risk_report_returns_dict(
        self,
        risk_service: RiskAssessorService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Risk report returns structured dict with breach cost estimate."""
        critical_discovery = make_discovery(
            tenant_id=tenant_id, status="assessed",
            risk_score=0.85, risk_level="critical"
        )
        mock_discovery_repo.list_by_tenant = AsyncMock(  # type: ignore[attr-defined]
            return_value=([critical_discovery], 1)
        )

        report = await risk_service.get_risk_report(tenant_id)

        assert report["total_discoveries"] == 1
        assert report["by_risk_level"]["critical"] == 1
        assert report["estimated_breach_cost_usd"] == 4_630_000


# ---------------------------------------------------------------------------
# MigrationService tests
# ---------------------------------------------------------------------------


class TestMigrationService:
    """Tests for MigrationService."""

    @pytest.mark.asyncio
    async def test_start_migration_creates_plan(
        self,
        migration_service: MigrationService,
        mock_discovery_repo: object,
        mock_migration_repo: object,
        mock_publisher: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Starting a migration creates a plan and transitions discovery to migrating."""
        employee_id = uuid.uuid4()
        discovery = make_discovery(
            tenant_id=tenant_id, status="assessed", detected_user_id=employee_id
        )
        plan = make_migration_plan(
            tenant_id=tenant_id,
            discovery_id=discovery.id,
            employee_id=employee_id,
        )

        mock_discovery_repo.get_by_id = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]
        mock_migration_repo.create = AsyncMock(return_value=plan)  # type: ignore[attr-defined]
        mock_discovery_repo.update_status = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]

        result = await migration_service.start_migration(
            tool_id=discovery.id,
            tenant_id=tenant_id,
            governed_tool_name="AumOS Enterprise AI Assistant",
        )

        assert result.id == plan.id
        mock_migration_repo.create.assert_awaited_once()  # type: ignore[attr-defined]
        mock_discovery_repo.update_status.assert_awaited_once_with(  # type: ignore[attr-defined]
            discovery_id=discovery.id,
            status="migrating",
            dismissed_reason=None,
        )
        mock_publisher.publish.assert_awaited_once()  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_start_migration_no_employee_id_raises(
        self,
        migration_service: MigrationService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Starting migration without identified employee raises ConflictError."""
        discovery = make_discovery(tenant_id=tenant_id, status="assessed", detected_user_id=None)
        mock_discovery_repo.get_by_id = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]

        with pytest.raises(ConflictError, match="no employee identified"):
            await migration_service.start_migration(
                tool_id=discovery.id,
                tenant_id=tenant_id,
                governed_tool_name="AumOS Enterprise AI Assistant",
            )

    @pytest.mark.asyncio
    async def test_start_migration_dismissed_discovery_raises(
        self,
        migration_service: MigrationService,
        mock_discovery_repo: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Starting migration on dismissed discovery raises ConflictError."""
        discovery = make_discovery(tenant_id=tenant_id, status="dismissed")
        mock_discovery_repo.get_by_id = AsyncMock(return_value=discovery)  # type: ignore[attr-defined]

        with pytest.raises(ConflictError):
            await migration_service.start_migration(
                tool_id=discovery.id,
                tenant_id=tenant_id,
                governed_tool_name="AumOS Enterprise AI Assistant",
            )

    @pytest.mark.asyncio
    async def test_complete_migration_transitions_discovery(
        self,
        migration_service: MigrationService,
        mock_migration_repo: object,
        mock_discovery_repo: object,
        mock_publisher: object,
        tenant_id: uuid.UUID,
    ) -> None:
        """Completing a migration transitions discovery to migrated and publishes event."""
        plan = make_migration_plan(tenant_id=tenant_id, status="in_progress")
        completed_plan = make_migration_plan(
            plan_id=plan.id, tenant_id=tenant_id, status="completed"
        )

        mock_migration_repo.get_by_id = AsyncMock(return_value=plan)  # type: ignore[attr-defined]
        mock_migration_repo.update_status = AsyncMock(return_value=completed_plan)  # type: ignore[attr-defined]
        mock_discovery_repo.update_status = AsyncMock()  # type: ignore[attr-defined]

        result = await migration_service.complete_migration(plan.id, tenant_id)

        assert result.status == "completed"
        mock_discovery_repo.update_status.assert_awaited_once_with(  # type: ignore[attr-defined]
            discovery_id=plan.discovery_id,
            status="migrated",
            dismissed_reason=None,
        )
        mock_publisher.publish.assert_awaited_once()  # type: ignore[attr-defined]
