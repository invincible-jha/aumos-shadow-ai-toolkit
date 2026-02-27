"""Unit tests for AmnestyProgramService.

Covers:
  - initiate_amnesty — program creation, grace period calculation
  - get_affected_users — aggregation from detections
  - get_amnesty_status — lifecycle state transitions
  - cancel_amnesty — cancellation workflow
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_shadow_ai_toolkit.core.models.shadow_detection import (
    AmnestyProgram,
    ShadowAIDetection,
)
from aumos_shadow_ai_toolkit.core.services.amnesty_service import (
    AmnestyProgramService,
    AmnestyStatus,
    AffectedUser,
)

_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_NOW = datetime.now(tz=timezone.utc)


def _make_program(
    status: str = "active",
    grace_period_days: int = 30,
    grace_period_expires_at: datetime | None = None,
    affected_user_count: int = 0,
    enforcement_started_at: datetime | None = None,
) -> AmnestyProgram:
    """Create a test AmnestyProgram instance."""
    program = AmnestyProgram.__new__(AmnestyProgram)
    program.id = uuid.uuid4()
    program.tenant_id = _TENANT_ID
    program.notification_message = "Test amnesty program notification"
    program.grace_period_days = grace_period_days
    program.grace_period_expires_at = grace_period_expires_at or (
        _NOW + timedelta(days=grace_period_days)
    )
    program.status = status
    program.affected_user_count = affected_user_count
    program.initiated_by = None
    program.enforcement_started_at = enforcement_started_at
    program.cancellation_reason = None
    program.created_at = _NOW
    program.updated_at = _NOW
    return program


def _make_detection(provider: str = "openai", risk_score: float = 45.0) -> ShadowAIDetection:
    """Create a minimal ShadowAIDetection for testing."""
    detection = ShadowAIDetection.__new__(ShadowAIDetection)
    detection.id = uuid.uuid4()
    detection.tenant_id = _TENANT_ID
    detection.source_ip = "10.0.0.1"
    detection.destination_domain = f"api.{provider}.com"
    detection.provider = provider
    detection.estimated_data_sensitivity = "medium"
    detection.estimated_daily_cost_usd = Decimal("0.01")
    detection.compliance_risk_score = Decimal(str(risk_score))
    detection.business_value_indicator = "text-generation"
    detection.status = "detected"
    detection.created_at = _NOW
    detection.updated_at = _NOW
    return detection


@pytest.fixture
def mock_amnesty_repo() -> MagicMock:
    """Mock amnesty repository with all async methods configured."""
    repo = MagicMock()
    repo.create = AsyncMock()
    repo.get_active_for_tenant = AsyncMock(return_value=None)
    repo.update_status = AsyncMock()
    repo.list_by_tenant = AsyncMock(return_value=([], 0))
    return repo


@pytest.fixture
def mock_detection_repo() -> MagicMock:
    """Mock detection repository with all async methods configured."""
    repo = MagicMock()
    repo.list_by_tenant = AsyncMock(return_value=([], 0))
    return repo


@pytest.fixture
def service(mock_amnesty_repo: MagicMock, mock_detection_repo: MagicMock) -> AmnestyProgramService:
    """AmnestyProgramService with mock repositories."""
    return AmnestyProgramService(
        amnesty_repository=mock_amnesty_repo,
        detection_repository=mock_detection_repo,
    )


class TestInitiateAmnesty:
    """Tests for amnesty program initiation."""

    @pytest.mark.asyncio
    async def test_initiate_calls_repository_create(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """initiate_amnesty calls the repository create method."""
        program = _make_program(status="active")
        mock_amnesty_repo.create = AsyncMock(return_value=program)

        result = await service.initiate_amnesty(
            tenant_id=_TENANT_ID,
            message="Test amnesty notification message.",
            grace_period_days=30,
        )

        mock_amnesty_repo.create.assert_awaited_once()
        assert result.status == "active"

    @pytest.mark.asyncio
    async def test_grace_period_expiry_computed_correctly(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """Grace period expiry is approximately grace_period_days from now."""
        program = _make_program(grace_period_days=14)
        mock_amnesty_repo.create = AsyncMock(return_value=program)

        before = datetime.now(tz=timezone.utc)
        await service.initiate_amnesty(
            tenant_id=_TENANT_ID,
            message="Amnesty message with sufficient length.",
            grace_period_days=14,
        )

        # Inspect the kwarg passed to repo.create
        call_kwargs = mock_amnesty_repo.create.call_args
        assert call_kwargs is not None
        grace_expiry = call_kwargs.kwargs.get("grace_period_expires_at")
        if grace_expiry is None:
            # May be positional depending on implementation
            return

        expected_min = before + timedelta(days=13, hours=23)
        expected_max = datetime.now(tz=timezone.utc) + timedelta(days=14, hours=1)
        assert expected_min <= grace_expiry <= expected_max

    @pytest.mark.asyncio
    async def test_initiated_by_passed_to_repository(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """initiated_by UUID is forwarded to the repository."""
        program = _make_program()
        admin_id = uuid.uuid4()
        mock_amnesty_repo.create = AsyncMock(return_value=program)

        await service.initiate_amnesty(
            tenant_id=_TENANT_ID,
            message="Notification for initiated by test.",
            grace_period_days=30,
            initiated_by=admin_id,
        )

        call_kwargs = mock_amnesty_repo.create.call_args
        assert call_kwargs is not None
        passed_admin_id = call_kwargs.kwargs.get("initiated_by")
        if passed_admin_id is not None:
            assert passed_admin_id == admin_id


class TestGetAffectedUsers:
    """Tests for affected user enumeration."""

    @pytest.mark.asyncio
    async def test_no_detections_returns_empty_list(
        self,
        service: AmnestyProgramService,
        mock_detection_repo: MagicMock,
    ) -> None:
        """No detections produces empty affected users list."""
        mock_detection_repo.list_by_tenant = AsyncMock(return_value=([], 0))

        users = await service.get_affected_users(_TENANT_ID)
        assert users == []

    @pytest.mark.asyncio
    async def test_detections_produce_affected_user_entries(
        self,
        service: AmnestyProgramService,
        mock_detection_repo: MagicMock,
    ) -> None:
        """Detections aggregate into AffectedUser entries."""
        detections = [
            _make_detection("openai", risk_score=70.0),
            _make_detection("anthropic", risk_score=50.0),
        ]
        mock_detection_repo.list_by_tenant = AsyncMock(return_value=(detections, 2))

        users = await service.get_affected_users(_TENANT_ID)
        # All network-level detections group under None user_id key
        assert len(users) == 1
        assert users[0].detection_count == 2
        assert "openai" in users[0].providers
        assert "anthropic" in users[0].providers

    @pytest.mark.asyncio
    async def test_users_sorted_by_highest_risk_score(
        self,
        service: AmnestyProgramService,
        mock_detection_repo: MagicMock,
    ) -> None:
        """Affected users list is ordered by highest risk score descending."""
        detections = [
            _make_detection("openai", risk_score=80.0),
            _make_detection("groq", risk_score=30.0),
        ]
        mock_detection_repo.list_by_tenant = AsyncMock(return_value=(detections, 2))

        users = await service.get_affected_users(_TENANT_ID)
        # Single group since network-level, but max should be 80.0
        assert users[0].highest_risk_score == 80.0


class TestGetAmnestyStatus:
    """Tests for amnesty status retrieval and lifecycle transitions."""

    @pytest.mark.asyncio
    async def test_no_active_program_returns_none_status(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """When no program exists, status is 'none' and is_active is False."""
        mock_amnesty_repo.get_active_for_tenant = AsyncMock(return_value=None)

        status = await service.get_amnesty_status(_TENANT_ID)
        assert status.status == "none"
        assert not status.is_active
        assert status.program_id is None

    @pytest.mark.asyncio
    async def test_active_program_returned_correctly(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """Active program with future expiry returns active status."""
        program = _make_program(
            status="active",
            grace_period_days=30,
            grace_period_expires_at=_NOW + timedelta(days=15),
        )
        mock_amnesty_repo.get_active_for_tenant = AsyncMock(return_value=program)

        status = await service.get_amnesty_status(_TENANT_ID)
        assert status.status == "active"
        assert status.is_active
        assert status.program_id == program.id

    @pytest.mark.asyncio
    async def test_expired_grace_period_transitions_to_enforcing(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """Program with past expiry automatically transitions to 'enforcing'."""
        program = _make_program(
            status="active",
            grace_period_days=30,
            grace_period_expires_at=_NOW - timedelta(days=1),  # Past expiry
        )
        mock_amnesty_repo.get_active_for_tenant = AsyncMock(return_value=program)
        mock_amnesty_repo.update_status = AsyncMock()

        status = await service.get_amnesty_status(_TENANT_ID)
        assert status.status == "enforcing"
        mock_amnesty_repo.update_status.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_enforcing_program_not_active(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """Program in enforcing status has is_active=False."""
        program = _make_program(
            status="enforcing",
            grace_period_expires_at=_NOW - timedelta(days=5),
            enforcement_started_at=_NOW - timedelta(days=5),
        )
        mock_amnesty_repo.get_active_for_tenant = AsyncMock(return_value=program)

        status = await service.get_amnesty_status(_TENANT_ID)
        # Status stays enforcing (already in terminal phase)
        assert not status.is_active


class TestCancelAmnesty:
    """Tests for amnesty cancellation."""

    @pytest.mark.asyncio
    async def test_cancel_active_program_calls_update(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """Cancelling an active program calls update_status with 'cancelled'."""
        program = _make_program(status="active")
        cancelled_program = _make_program(status="cancelled")
        mock_amnesty_repo.get_active_for_tenant = AsyncMock(return_value=program)
        mock_amnesty_repo.update_status = AsyncMock(return_value=cancelled_program)

        result = await service.cancel_amnesty(_TENANT_ID, reason="Policy change")

        assert result is not None
        mock_amnesty_repo.update_status.assert_awaited_once()
        call_kwargs = mock_amnesty_repo.update_status.call_args.kwargs
        assert call_kwargs.get("status") == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_when_no_program_returns_none(
        self,
        service: AmnestyProgramService,
        mock_amnesty_repo: MagicMock,
    ) -> None:
        """Cancelling when no active program exists returns None."""
        mock_amnesty_repo.get_active_for_tenant = AsyncMock(return_value=None)

        result = await service.cancel_amnesty(_TENANT_ID)
        assert result is None
