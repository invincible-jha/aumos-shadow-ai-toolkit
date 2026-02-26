"""Business logic services for the AumOS Shadow AI Toolkit.

All services depend on repository and adapter interfaces (not concrete
implementations) and receive dependencies via constructor injection.
No framework code (FastAPI, SQLAlchemy) belongs here.

Key invariants enforced by services:
- No content inspection: only network metadata is processed.
- Idempotent discovery: re-detections update counters, not create duplicates.
- Risk scoring is applied immediately after detection, before status=assessed.
- Migration plans are scoped to a single discovery+employee pair.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.errors import ConflictError, ErrorCode, NotFoundError
from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.core.interfaces import (
    IDiscoveryRepository,
    IGovernanceEngineAdapter,
    IMigrationRepository,
    INetworkScannerAdapter,
    IScanResultRepository,
    IUsageMetricRepository,
)
from aumos_shadow_ai_toolkit.core.models import (
    MigrationPlan,
    ScanResult,
    ShadowAIDiscovery,
)

logger = get_logger(__name__)

# Valid discovery status values
VALID_DISCOVERY_STATUSES: frozenset[str] = frozenset(
    {"detected", "assessed", "notified", "migrating", "migrated", "dismissed"}
)

# Terminal statuses — no further transitions allowed
TERMINAL_DISCOVERY_STATUSES: frozenset[str] = frozenset({"migrated", "dismissed"})

# Risk level labels
RISK_LEVEL_CRITICAL = "critical"
RISK_LEVEL_HIGH = "high"
RISK_LEVEL_MEDIUM = "medium"
RISK_LEVEL_LOW = "low"


def _compute_risk_level(
    risk_score: float,
    threshold_critical: float,
    threshold_high: float,
    threshold_medium: float,
) -> str:
    """Map a numeric risk score to a categorical risk level.

    Args:
        risk_score: Composite risk score (0.0–1.0).
        threshold_critical: Score at or above which the level is critical.
        threshold_high: Score at or above which the level is high.
        threshold_medium: Score at or above which the level is medium.

    Returns:
        Risk level string: critical | high | medium | low.
    """
    if risk_score >= threshold_critical:
        return RISK_LEVEL_CRITICAL
    if risk_score >= threshold_high:
        return RISK_LEVEL_HIGH
    if risk_score >= threshold_medium:
        return RISK_LEVEL_MEDIUM
    return RISK_LEVEL_LOW


class DiscoveryService:
    """Orchestrate detection, deduplication, and lifecycle of shadow AI discoveries.

    Coordinates the network scanner adapter with the discovery repository to
    produce a deduplicated inventory of shadow AI usage across the enterprise.
    """

    def __init__(
        self,
        discovery_repo: IDiscoveryRepository,
        scan_repo: IScanResultRepository,
        scanner_adapter: INetworkScannerAdapter,
        event_publisher: EventPublisher,
        known_ai_endpoints: list[str],
        scan_timeout_seconds: int = 300,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            discovery_repo: ShadowAIDiscovery persistence.
            scan_repo: ScanResult persistence.
            scanner_adapter: Network traffic analysis adapter.
            event_publisher: Kafka event publisher.
            known_ai_endpoints: List of AI API domain patterns to check.
            scan_timeout_seconds: Maximum scan duration in seconds.
        """
        self._discoveries = discovery_repo
        self._scans = scan_repo
        self._scanner = scanner_adapter
        self._publisher = event_publisher
        self._known_endpoints = known_ai_endpoints
        self._scan_timeout = scan_timeout_seconds

    async def initiate_scan(
        self,
        tenant_id: uuid.UUID,
        scan_type: str = "manual",
    ) -> ScanResult:
        """Initiate a network scan to detect shadow AI tool usage.

        Creates a scan result record, runs the network scanner, and processes
        detections into discoveries. Re-detections update existing records.

        Args:
            tenant_id: Owning tenant UUID.
            scan_type: scheduled | manual | triggered.

        Returns:
            Completed ScanResult with new_discoveries_count populated.
        """
        started_at = datetime.now(tz=timezone.utc)

        scan = await self._scans.create(
            tenant_id=tenant_id,
            scan_type=scan_type,
            scan_parameters={
                "endpoints_checked": self._known_endpoints,
                "timeout_seconds": self._scan_timeout,
            },
        )

        logger.info(
            "Network scan initiated",
            tenant_id=str(tenant_id),
            scan_id=str(scan.id),
            scan_type=scan_type,
            endpoint_count=len(self._known_endpoints),
        )

        try:
            detections = await self._scanner.scan(
                tenant_id=tenant_id,
                endpoints_to_check=self._known_endpoints,
                timeout_seconds=self._scan_timeout,
            )

            new_count = 0
            for detection in detections:
                is_new = await self._process_detection(
                    tenant_id=tenant_id,
                    scan_id=scan.id,
                    detection=detection,
                )
                if is_new:
                    new_count += 1

            completed_at = datetime.now(tz=timezone.utc)
            duration = int((completed_at - started_at).total_seconds())

            scan = await self._scans.complete(
                scan_id=scan.id,
                new_discoveries_count=new_count,
                total_endpoints_checked=len(self._known_endpoints),
                duration_seconds=duration,
            )

            logger.info(
                "Network scan completed",
                tenant_id=str(tenant_id),
                scan_id=str(scan.id),
                new_discoveries=new_count,
                total_detections=len(detections),
                duration_seconds=duration,
            )

        except Exception as exc:
            scan = await self._scans.fail(
                scan_id=scan.id,
                error_message=str(exc),
            )
            logger.error(
                "Network scan failed",
                tenant_id=str(tenant_id),
                scan_id=str(scan.id),
                error=str(exc),
            )
            raise

        return scan

    async def _process_detection(
        self,
        tenant_id: uuid.UUID,
        scan_id: uuid.UUID,
        detection: dict[str, Any],
    ) -> bool:
        """Process a single detection from the network scanner.

        Deduplicates against existing discoveries. If a match exists, increments
        counters. If new, creates a discovery record and publishes an event.

        Args:
            tenant_id: Owning tenant UUID.
            scan_id: Parent scan result UUID.
            detection: Detection dict from the scanner adapter.

        Returns:
            True if this is a new discovery, False if an existing one was updated.
        """
        tool_name: str = detection["tool_name"]
        detected_user_id_str: str | None = detection.get("detected_user_id")
        detected_user_id: uuid.UUID | None = (
            uuid.UUID(detected_user_id_str) if detected_user_id_str else None
        )

        existing = await self._discoveries.find_existing(
            tenant_id=tenant_id,
            tool_name=tool_name,
            detected_user_id=detected_user_id,
        )

        if existing and existing.status not in TERMINAL_DISCOVERY_STATUSES:
            # Update counters on re-detection
            await self._discoveries.increment_request_count(
                discovery_id=existing.id,
                request_count_delta=detection.get("request_count", 1),
                estimated_volume_kb_delta=detection.get("estimated_volume_kb", 0),
                last_seen_at=detection.get("last_seen_at", datetime.now(tz=timezone.utc)),
            )
            return False

        # New discovery
        discovery = await self._discoveries.create(
            tenant_id=tenant_id,
            tool_name=tool_name,
            api_endpoint=detection["api_endpoint"],
            detection_method=detection["detection_method"],
            detected_user_id=detected_user_id,
            scan_result_id=scan_id,
        )

        await self._publisher.publish(
            Topics.SHADOW_AI_EVENTS,
            {
                "event_type": "shadow_ai.discovered",
                "tenant_id": str(tenant_id),
                "discovery_id": str(discovery.id),
                "tool_name": tool_name,
                "api_endpoint": detection["api_endpoint"],
                "detection_method": detection["detection_method"],
                "detected_user_id": str(detected_user_id) if detected_user_id else None,
                "scan_id": str(scan_id),
            },
        )

        logger.info(
            "New shadow AI discovery",
            tenant_id=str(tenant_id),
            discovery_id=str(discovery.id),
            tool_name=tool_name,
            detection_method=detection["detection_method"],
        )

        return True

    async def get_discovery(
        self, discovery_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> ShadowAIDiscovery:
        """Retrieve a shadow AI discovery by ID.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Requesting tenant for RLS enforcement.

        Returns:
            ShadowAIDiscovery.

        Raises:
            NotFoundError: If discovery not found.
        """
        discovery = await self._discoveries.get_by_id(discovery_id, tenant_id)
        if discovery is None:
            raise NotFoundError(
                message=f"Shadow AI discovery {discovery_id} not found.",
                error_code=ErrorCode.NOT_FOUND,
            )
        return discovery

    async def list_discoveries(
        self,
        tenant_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
        status: str | None = None,
        risk_level: str | None = None,
    ) -> tuple[list[ShadowAIDiscovery], int]:
        """List shadow AI discoveries for a tenant with pagination.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.
            status: Optional status filter.
            risk_level: Optional risk level filter.

        Returns:
            Tuple of (discoveries, total_count).
        """
        return await self._discoveries.list_by_tenant(
            tenant_id=tenant_id,
            page=page,
            page_size=page_size,
            status=status,
            risk_level=risk_level,
        )

    async def dismiss_discovery(
        self,
        discovery_id: uuid.UUID,
        tenant_id: uuid.UUID,
        reason: str | None = None,
    ) -> ShadowAIDiscovery:
        """Dismiss a shadow AI discovery, removing it from active monitoring.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Requesting tenant.
            reason: Optional reason for dismissal.

        Returns:
            Updated ShadowAIDiscovery with status=dismissed.

        Raises:
            NotFoundError: If discovery not found.
            ConflictError: If discovery is already in a terminal state.
        """
        discovery = await self.get_discovery(discovery_id, tenant_id)

        if discovery.status in TERMINAL_DISCOVERY_STATUSES:
            raise ConflictError(
                message=f"Discovery {discovery_id} is already in terminal status '{discovery.status}'.",
                error_code=ErrorCode.INVALID_OPERATION,
            )

        discovery = await self._discoveries.update_status(
            discovery_id=discovery_id,
            status="dismissed",
            dismissed_reason=reason,
        )

        logger.info(
            "Shadow AI discovery dismissed",
            discovery_id=str(discovery_id),
            tenant_id=str(tenant_id),
            reason=reason,
        )

        return discovery


class RiskAssessorService:
    """Assess and score the risk of detected shadow AI tool usage.

    Computes composite risk scores from data sensitivity and compliance exposure
    using the governance engine policy adapter.
    """

    def __init__(
        self,
        discovery_repo: IDiscoveryRepository,
        governance_adapter: IGovernanceEngineAdapter,
        event_publisher: EventPublisher,
        threshold_critical: float = 0.7,
        threshold_high: float = 0.5,
        threshold_medium: float = 0.3,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            discovery_repo: ShadowAIDiscovery persistence.
            governance_adapter: Governance engine risk evaluation.
            event_publisher: Kafka event publisher.
            threshold_critical: Risk score threshold for critical rating.
            threshold_high: Risk score threshold for high rating.
            threshold_medium: Risk score threshold for medium rating.
        """
        self._discoveries = discovery_repo
        self._governance = governance_adapter
        self._publisher = event_publisher
        self._threshold_critical = threshold_critical
        self._threshold_high = threshold_high
        self._threshold_medium = threshold_medium

    async def assess_discovery(
        self,
        discovery_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> ShadowAIDiscovery:
        """Evaluate and persist risk assessment for a discovery.

        Calls the governance engine to compute data sensitivity and compliance
        exposure, then persists the risk score and level on the discovery record.

        Args:
            discovery_id: Discovery UUID to assess.
            tenant_id: Requesting tenant.

        Returns:
            Updated ShadowAIDiscovery with risk assessment populated.

        Raises:
            NotFoundError: If discovery not found.
        """
        discovery = await self._discoveries.get_by_id(discovery_id, tenant_id)
        if discovery is None:
            raise NotFoundError(
                message=f"Shadow AI discovery {discovery_id} not found.",
                error_code=ErrorCode.NOT_FOUND,
            )

        risk_result = await self._governance.evaluate_risk(
            tenant_id=tenant_id,
            tool_name=discovery.tool_name,
            api_endpoint=discovery.api_endpoint,
            detection_metadata={
                "request_count": discovery.request_count,
                "estimated_data_volume_kb": discovery.estimated_data_volume_kb,
                "detection_method": discovery.detection_method,
            },
        )

        risk_score: float = risk_result.get("risk_score", 0.5)
        risk_level = _compute_risk_level(
            risk_score,
            self._threshold_critical,
            self._threshold_high,
            self._threshold_medium,
        )

        discovery = await self._discoveries.update_risk_assessment(
            discovery_id=discovery_id,
            risk_score=risk_score,
            risk_level=risk_level,
            data_sensitivity=risk_result.get("data_sensitivity", "unknown"),
            compliance_exposure=risk_result.get("compliance_exposure", []),
            risk_details=risk_result.get("details", {}),
        )

        # Transition to assessed status
        discovery = await self._discoveries.update_status(
            discovery_id=discovery_id,
            status="assessed",
            dismissed_reason=None,
        )

        logger.info(
            "Shadow AI discovery assessed",
            discovery_id=str(discovery_id),
            tenant_id=str(tenant_id),
            risk_score=risk_score,
            risk_level=risk_level,
        )

        return discovery

    async def get_risk_report(
        self, tenant_id: uuid.UUID
    ) -> dict[str, Any]:
        """Generate an aggregated risk report for a tenant.

        Aggregates discoveries by risk level and computes estimated breach
        cost exposure based on the $4.63M average breach cost benchmark.

        Args:
            tenant_id: Requesting tenant.

        Returns:
            Risk report dict with counts, exposure estimates, and top risks.
        """
        # Retrieve all active (non-dismissed) discoveries
        active_discoveries, total = await self._discoveries.list_by_tenant(
            tenant_id=tenant_id,
            page=1,
            page_size=1000,
            status=None,
            risk_level=None,
        )

        by_level: dict[str, int] = {
            RISK_LEVEL_CRITICAL: 0,
            RISK_LEVEL_HIGH: 0,
            RISK_LEVEL_MEDIUM: 0,
            RISK_LEVEL_LOW: 0,
            "unknown": 0,
        }
        for discovery in active_discoveries:
            level = discovery.risk_level
            if level in by_level:
                by_level[level] += 1
            else:
                by_level["unknown"] += 1

        # Estimated breach cost exposure: $4.63M per critical, $1M per high (rough model)
        estimated_exposure_usd = (
            by_level[RISK_LEVEL_CRITICAL] * 4_630_000
            + by_level[RISK_LEVEL_HIGH] * 1_000_000
            + by_level[RISK_LEVEL_MEDIUM] * 250_000
        )

        top_risks = [
            {
                "discovery_id": str(d.id),
                "tool_name": d.tool_name,
                "risk_score": d.risk_score,
                "risk_level": d.risk_level,
                "compliance_exposure": d.compliance_exposure,
            }
            for d in sorted(active_discoveries, key=lambda d: d.risk_score, reverse=True)[:10]
        ]

        return {
            "total_discoveries": total,
            "by_risk_level": by_level,
            "estimated_breach_cost_usd": estimated_exposure_usd,
            "top_risks": top_risks,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }


class MigrationService:
    """Manage migration workflows from shadow AI tools to governed alternatives.

    Creates and tracks migration plans, coordinating with the model registry
    for governed alternatives and the approval workflow for multi-stakeholder sign-off.
    """

    def __init__(
        self,
        discovery_repo: IDiscoveryRepository,
        migration_repo: IMigrationRepository,
        event_publisher: EventPublisher,
        migration_expiry_days: int = 90,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            discovery_repo: ShadowAIDiscovery persistence.
            migration_repo: MigrationPlan persistence.
            event_publisher: Kafka event publisher.
            migration_expiry_days: Days before an inactive plan expires.
        """
        self._discoveries = discovery_repo
        self._migrations = migration_repo
        self._publisher = event_publisher
        self._expiry_days = migration_expiry_days

    async def start_migration(
        self,
        tool_id: uuid.UUID,
        tenant_id: uuid.UUID,
        governed_tool_name: str,
        governed_model_id: uuid.UUID | None = None,
        employee_id: uuid.UUID | None = None,
    ) -> MigrationPlan:
        """Create a migration plan for an employee to move to a governed alternative.

        Args:
            tool_id: Discovery UUID (the shadow AI tool to migrate away from).
            tenant_id: Requesting tenant.
            governed_tool_name: Name of the sanctioned alternative.
            governed_model_id: Optional model registry UUID for the governed tool.
            employee_id: Optional employee UUID (defaults to detection user).

        Returns:
            Newly created MigrationPlan in pending status.

        Raises:
            NotFoundError: If discovery not found.
            ConflictError: If discovery is already migrated or dismissed.
        """
        discovery = await self._discoveries.get_by_id(tool_id, tenant_id)
        if discovery is None:
            raise NotFoundError(
                message=f"Shadow AI discovery {tool_id} not found.",
                error_code=ErrorCode.NOT_FOUND,
            )

        if discovery.status in TERMINAL_DISCOVERY_STATUSES:
            raise ConflictError(
                message=f"Cannot start migration — discovery {tool_id} is '{discovery.status}'.",
                error_code=ErrorCode.INVALID_OPERATION,
            )

        migrating_employee_id = employee_id or discovery.detected_user_id
        if migrating_employee_id is None:
            raise ConflictError(
                message="Cannot start migration — no employee identified in the discovery.",
                error_code=ErrorCode.INVALID_OPERATION,
            )

        expires_at = datetime.now(tz=timezone.utc) + timedelta(days=self._expiry_days)

        migration_steps = [
            {"step": "notify_employee", "status": "pending"},
            {"step": "provision_access", "status": "pending"},
            {"step": "training_completion", "status": "pending"},
            {"step": "shadow_tool_block", "status": "pending"},
        ]

        plan = await self._migrations.create(
            tenant_id=tenant_id,
            discovery_id=tool_id,
            employee_id=migrating_employee_id,
            shadow_tool_name=discovery.tool_name,
            governed_tool_name=governed_tool_name,
            governed_model_id=governed_model_id,
            migration_steps=migration_steps,
            expires_at=expires_at,
        )

        # Transition discovery to migrating status
        await self._discoveries.update_status(
            discovery_id=tool_id,
            status="migrating",
            dismissed_reason=None,
        )

        await self._publisher.publish(
            Topics.SHADOW_AI_EVENTS,
            {
                "event_type": "shadow_ai.migration_started",
                "tenant_id": str(tenant_id),
                "discovery_id": str(tool_id),
                "migration_plan_id": str(plan.id),
                "employee_id": str(migrating_employee_id),
                "shadow_tool": discovery.tool_name,
                "governed_tool": governed_tool_name,
                "expires_at": expires_at.isoformat(),
            },
        )

        logger.info(
            "Migration plan created",
            tenant_id=str(tenant_id),
            plan_id=str(plan.id),
            discovery_id=str(tool_id),
            employee_id=str(migrating_employee_id),
            governed_tool=governed_tool_name,
        )

        return plan

    async def complete_migration(
        self,
        plan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        notes: str | None = None,
    ) -> MigrationPlan:
        """Mark a migration plan as successfully completed.

        Updates both the migration plan and the parent discovery status.

        Args:
            plan_id: MigrationPlan UUID.
            tenant_id: Requesting tenant.
            notes: Optional completion notes.

        Returns:
            Updated MigrationPlan with status=completed.

        Raises:
            NotFoundError: If plan not found.
            ConflictError: If plan is already in a terminal state.
        """
        plan = await self._migrations.get_by_id(plan_id, tenant_id)
        if plan is None:
            raise NotFoundError(
                message=f"Migration plan {plan_id} not found.",
                error_code=ErrorCode.NOT_FOUND,
            )

        if plan.status in {"completed", "expired", "failed"}:
            raise ConflictError(
                message=f"Migration plan {plan_id} is already '{plan.status}'.",
                error_code=ErrorCode.INVALID_OPERATION,
            )

        completed_at = datetime.now(tz=timezone.utc)
        plan = await self._migrations.update_status(
            plan_id=plan_id,
            status="completed",
            completed_at=completed_at,
            notes=notes,
        )

        # Mark discovery as fully migrated
        await self._discoveries.update_status(
            discovery_id=plan.discovery_id,
            status="migrated",
            dismissed_reason=None,
        )

        await self._publisher.publish(
            Topics.SHADOW_AI_EVENTS,
            {
                "event_type": "shadow_ai.migration_completed",
                "tenant_id": str(tenant_id),
                "discovery_id": str(plan.discovery_id),
                "migration_plan_id": str(plan_id),
                "employee_id": str(plan.employee_id),
                "governed_tool": plan.governed_tool_name,
                "completed_at": completed_at.isoformat(),
            },
        )

        logger.info(
            "Migration plan completed",
            tenant_id=str(tenant_id),
            plan_id=str(plan_id),
            discovery_id=str(plan.discovery_id),
            governed_tool=plan.governed_tool_name,
        )

        return plan

    async def get_migration_plan(
        self, plan_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> MigrationPlan:
        """Retrieve a migration plan by ID.

        Args:
            plan_id: MigrationPlan UUID.
            tenant_id: Requesting tenant.

        Returns:
            MigrationPlan.

        Raises:
            NotFoundError: If plan not found.
        """
        plan = await self._migrations.get_by_id(plan_id, tenant_id)
        if plan is None:
            raise NotFoundError(
                message=f"Migration plan {plan_id} not found.",
                error_code=ErrorCode.NOT_FOUND,
            )
        return plan


class DashboardService:
    """Provide usage analytics and trend data for the shadow AI dashboard.

    Aggregates discovery and migration data into dashboard-ready statistics
    for the analytics endpoint.
    """

    def __init__(
        self,
        metric_repo: IUsageMetricRepository,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            metric_repo: UsageMetric persistence and aggregation.
        """
        self._metrics = metric_repo

    async def get_dashboard(
        self,
        tenant_id: uuid.UUID,
        days: int = 30,
    ) -> dict[str, Any]:
        """Retrieve dashboard analytics for the last N days.

        Args:
            tenant_id: Requesting tenant.
            days: Number of days to include in the aggregation.

        Returns:
            Dashboard dict with usage trends, risk distribution, and migration stats.
        """
        stats = await self._metrics.get_dashboard_stats(
            tenant_id=tenant_id,
            days=days,
        )

        logger.info(
            "Dashboard stats retrieved",
            tenant_id=str(tenant_id),
            days=days,
        )

        return stats
