"""Shared pytest fixtures for the aumos-shadow-ai-toolkit test suite.

Provides mock implementations of all interfaces, avoiding real database,
Kafka, or network connections in unit tests.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aumos_shadow_ai_toolkit.core.models import (
    MigrationPlan,
    ScanResult,
    ShadowAIDiscovery,
)
from aumos_shadow_ai_toolkit.core.services import (
    DashboardService,
    DiscoveryService,
    MigrationService,
    RiskAssessorService,
)


# ---------------------------------------------------------------------------
# Test data factories
# ---------------------------------------------------------------------------


def make_discovery(
    discovery_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    tool_name: str = "ChatGPT / OpenAI API",
    api_endpoint: str = "api.openai.com",
    detection_method: str = "dns_pattern",
    status: str = "detected",
    risk_score: float = 0.0,
    risk_level: str = "unknown",
    detected_user_id: uuid.UUID | None = None,
) -> ShadowAIDiscovery:
    """Create a test ShadowAIDiscovery instance.

    Args:
        discovery_id: Optional discovery UUID (auto-generated if None).
        tenant_id: Optional tenant UUID (auto-generated if None).
        tool_name: AI tool name.
        api_endpoint: Detected API endpoint.
        detection_method: Detection method used.
        status: Current status.
        risk_score: Composite risk score.
        risk_level: Risk level category.
        detected_user_id: Optional employee UUID.

    Returns:
        ShadowAIDiscovery instance with test data.
    """
    discovery = ShadowAIDiscovery.__new__(ShadowAIDiscovery)
    discovery.id = discovery_id or uuid.uuid4()
    discovery.tenant_id = tenant_id or uuid.uuid4()
    discovery.tool_name = tool_name
    discovery.api_endpoint = api_endpoint
    discovery.detection_method = detection_method
    discovery.detected_user_id = detected_user_id
    discovery.risk_score = risk_score
    discovery.risk_level = risk_level
    discovery.data_sensitivity = "unknown"
    discovery.compliance_exposure = []
    discovery.status = status
    discovery.first_seen_at = datetime.now(tz=timezone.utc)
    discovery.last_seen_at = datetime.now(tz=timezone.utc)
    discovery.request_count = 1
    discovery.estimated_data_volume_kb = 0
    discovery.scan_result_id = None
    discovery.risk_details = {}
    discovery.dismissed_reason = None
    discovery.created_at = datetime.now(tz=timezone.utc)
    discovery.updated_at = datetime.now(tz=timezone.utc)
    discovery.migration_plans = []
    discovery.scan_result = None
    return discovery


def make_migration_plan(
    plan_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    discovery_id: uuid.UUID | None = None,
    employee_id: uuid.UUID | None = None,
    status: str = "pending",
) -> MigrationPlan:
    """Create a test MigrationPlan instance.

    Args:
        plan_id: Optional plan UUID (auto-generated if None).
        tenant_id: Optional tenant UUID (auto-generated if None).
        discovery_id: Optional parent discovery UUID.
        employee_id: Optional employee UUID.
        status: Current status.

    Returns:
        MigrationPlan instance with test data.
    """
    plan = MigrationPlan.__new__(MigrationPlan)
    plan.id = plan_id or uuid.uuid4()
    plan.tenant_id = tenant_id or uuid.uuid4()
    plan.discovery_id = discovery_id or uuid.uuid4()
    plan.employee_id = employee_id or uuid.uuid4()
    plan.shadow_tool_name = "ChatGPT / OpenAI API"
    plan.governed_tool_name = "AumOS Enterprise AI Assistant"
    plan.governed_model_id = None
    plan.status = status
    plan.approval_workflow_id = None
    plan.migration_steps = [
        {"step": "notify_employee", "status": "pending"},
        {"step": "provision_access", "status": "pending"},
        {"step": "training_completion", "status": "pending"},
        {"step": "shadow_tool_block", "status": "pending"},
    ]
    plan.expires_at = datetime.now(tz=timezone.utc) + timedelta(days=90)
    plan.completed_at = None
    plan.notes = None
    plan.created_at = datetime.now(tz=timezone.utc)
    plan.updated_at = datetime.now(tz=timezone.utc)
    return plan


def make_scan_result(
    scan_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    status: str = "completed",
) -> ScanResult:
    """Create a test ScanResult instance.

    Args:
        scan_id: Optional scan UUID (auto-generated if None).
        tenant_id: Optional tenant UUID (auto-generated if None).
        status: Current status.

    Returns:
        ScanResult instance with test data.
    """
    scan = ScanResult.__new__(ScanResult)
    scan.id = scan_id or uuid.uuid4()
    scan.tenant_id = tenant_id or uuid.uuid4()
    scan.scan_type = "manual"
    scan.status = status
    scan.started_at = datetime.now(tz=timezone.utc)
    scan.completed_at = datetime.now(tz=timezone.utc)
    scan.duration_seconds = 5
    scan.new_discoveries_count = 0
    scan.total_endpoints_checked = 10
    scan.error_message = None
    scan.scan_parameters = {}
    scan.created_at = datetime.now(tz=timezone.utc)
    scan.updated_at = datetime.now(tz=timezone.utc)
    scan.discoveries = []
    return scan


# ---------------------------------------------------------------------------
# Mock repository fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_discovery_repo() -> MagicMock:
    """Mock IDiscoveryRepository.

    Returns:
        MagicMock with all async methods pre-configured.
    """
    repo = MagicMock()
    repo.create = AsyncMock()
    repo.get_by_id = AsyncMock()
    repo.list_by_tenant = AsyncMock(return_value=([], 0))
    repo.update_status = AsyncMock()
    repo.update_risk_assessment = AsyncMock()
    repo.find_existing = AsyncMock(return_value=None)
    repo.increment_request_count = AsyncMock()
    return repo


@pytest.fixture
def mock_migration_repo() -> MagicMock:
    """Mock IMigrationRepository.

    Returns:
        MagicMock with all async methods pre-configured.
    """
    repo = MagicMock()
    repo.create = AsyncMock()
    repo.get_by_id = AsyncMock()
    repo.list_by_discovery = AsyncMock(return_value=[])
    repo.update_status = AsyncMock()
    repo.set_approval_workflow_id = AsyncMock()
    return repo


@pytest.fixture
def mock_scan_repo() -> MagicMock:
    """Mock IScanResultRepository.

    Returns:
        MagicMock with all async methods pre-configured.
    """
    repo = MagicMock()
    repo.create = AsyncMock()
    repo.complete = AsyncMock()
    repo.fail = AsyncMock()
    repo.list_by_tenant = AsyncMock(return_value=([], 0))
    return repo


@pytest.fixture
def mock_metric_repo() -> MagicMock:
    """Mock IUsageMetricRepository.

    Returns:
        MagicMock with all async methods pre-configured.
    """
    repo = MagicMock()
    repo.upsert_daily = AsyncMock()
    repo.get_dashboard_stats = AsyncMock(
        return_value={
            "total_discoveries": 0,
            "active_users": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "migrations_started": 0,
            "migrations_completed": 0,
            "estimated_breach_cost_usd": 0.0,
            "top_tools": [],
            "trend": [],
        }
    )
    return repo


@pytest.fixture
def mock_scanner() -> MagicMock:
    """Mock INetworkScannerAdapter.

    Returns:
        MagicMock with scan method pre-configured.
    """
    adapter = MagicMock()
    adapter.scan = AsyncMock(return_value=[])
    return adapter


@pytest.fixture
def mock_governance() -> MagicMock:
    """Mock IGovernanceEngineAdapter.

    Returns:
        MagicMock with evaluate_risk method pre-configured.
    """
    adapter = MagicMock()
    adapter.evaluate_risk = AsyncMock(
        return_value={
            "risk_score": 0.75,
            "risk_level": "critical",
            "data_sensitivity": "pii",
            "compliance_exposure": ["GDPR", "HIPAA"],
            "details": {"reason": "Sensitive PII data suspected"},
        }
    )
    return adapter


@pytest.fixture
def mock_publisher() -> MagicMock:
    """Mock EventPublisher.

    Returns:
        MagicMock with publish method pre-configured.
    """
    publisher = MagicMock()
    publisher.publish = AsyncMock()
    return publisher


# ---------------------------------------------------------------------------
# Service fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def discovery_service(
    mock_discovery_repo: MagicMock,
    mock_scan_repo: MagicMock,
    mock_scanner: MagicMock,
    mock_publisher: MagicMock,
) -> DiscoveryService:
    """Create a DiscoveryService with mock dependencies.

    Returns:
        DiscoveryService instance ready for unit testing.
    """
    return DiscoveryService(
        discovery_repo=mock_discovery_repo,
        scan_repo=mock_scan_repo,
        scanner_adapter=mock_scanner,
        event_publisher=mock_publisher,
        known_ai_endpoints=["api.openai.com", "api.anthropic.com"],
        scan_timeout_seconds=10,
    )


@pytest.fixture
def risk_service(
    mock_discovery_repo: MagicMock,
    mock_governance: MagicMock,
    mock_publisher: MagicMock,
) -> RiskAssessorService:
    """Create a RiskAssessorService with mock dependencies.

    Returns:
        RiskAssessorService instance ready for unit testing.
    """
    return RiskAssessorService(
        discovery_repo=mock_discovery_repo,
        governance_adapter=mock_governance,
        event_publisher=mock_publisher,
        threshold_critical=0.7,
        threshold_high=0.5,
        threshold_medium=0.3,
    )


@pytest.fixture
def migration_service(
    mock_discovery_repo: MagicMock,
    mock_migration_repo: MagicMock,
    mock_publisher: MagicMock,
) -> MigrationService:
    """Create a MigrationService with mock dependencies.

    Returns:
        MigrationService instance ready for unit testing.
    """
    return MigrationService(
        discovery_repo=mock_discovery_repo,
        migration_repo=mock_migration_repo,
        event_publisher=mock_publisher,
        migration_expiry_days=90,
    )


@pytest.fixture
def dashboard_service(mock_metric_repo: MagicMock) -> DashboardService:
    """Create a DashboardService with mock dependencies.

    Returns:
        DashboardService instance ready for unit testing.
    """
    return DashboardService(metric_repo=mock_metric_repo)


# ---------------------------------------------------------------------------
# Shared tenant fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def tenant_id() -> uuid.UUID:
    """Fixed tenant UUID for tests.

    Returns:
        Deterministic tenant UUID for consistent test assertions.
    """
    return uuid.UUID("00000000-0000-0000-0000-000000000001")
