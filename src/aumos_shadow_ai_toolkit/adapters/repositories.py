"""SQLAlchemy repository implementations for the Shadow AI Toolkit.

All repositories extend BaseRepository from aumos-common and implement
the Protocol interfaces defined in core/interfaces.py.
"""

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.database import BaseRepository, get_db_session
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.core.interfaces import (
    IDiscoveryRepository,
    IMigrationRepository,
    IScanResultRepository,
    IUsageMetricRepository,
)
from aumos_shadow_ai_toolkit.core.models import (
    MigrationPlan,
    ScanResult,
    ShadowAIDiscovery,
    UsageMetric,
)

logger = get_logger(__name__)


class DiscoveryRepository(BaseRepository[ShadowAIDiscovery], IDiscoveryRepository):
    """Repository for ShadowAIDiscovery persistence.

    Extends BaseRepository which handles tenant-scoped DB sessions,
    pagination helpers, and common CRUD operations.
    """

    model_class = ShadowAIDiscovery

    async def create(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        detection_method: str,
        detected_user_id: uuid.UUID | None,
        scan_result_id: uuid.UUID | None,
    ) -> ShadowAIDiscovery:
        """Create and persist a new shadow AI discovery.

        Args:
            tenant_id: Owning tenant UUID.
            tool_name: Human-readable name of the detected AI tool.
            api_endpoint: Detected API domain/endpoint.
            detection_method: How the tool was detected.
            detected_user_id: Optional UUID of the employee detected.
            scan_result_id: Optional UUID of the scan that found it.

        Returns:
            Newly created ShadowAIDiscovery in detected status.
        """
        now = datetime.now(tz=timezone.utc)
        async with get_db_session(tenant_id) as session:
            discovery = ShadowAIDiscovery(
                tenant_id=tenant_id,
                tool_name=tool_name,
                api_endpoint=api_endpoint,
                detection_method=detection_method,
                detected_user_id=detected_user_id,
                scan_result_id=scan_result_id,
                status="detected",
                first_seen_at=now,
                last_seen_at=now,
                request_count=1,
            )
            session.add(discovery)
            await session.flush()
            await session.refresh(discovery)
            return discovery

    async def get_by_id(
        self, discovery_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> ShadowAIDiscovery | None:
        """Retrieve a discovery by UUID within a tenant.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Requesting tenant for RLS enforcement.

        Returns:
            ShadowAIDiscovery or None if not found.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(ShadowAIDiscovery).where(
                    ShadowAIDiscovery.id == discovery_id,
                    ShadowAIDiscovery.tenant_id == tenant_id,
                )
            )
            return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
        status: str | None,
        risk_level: str | None,
    ) -> tuple[list[ShadowAIDiscovery], int]:
        """List discoveries for a tenant with pagination and optional filters.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.
            status: Optional status filter.
            risk_level: Optional risk level filter.

        Returns:
            Tuple of (discoveries, total_count).
        """
        async with get_db_session(tenant_id) as session:
            query = select(ShadowAIDiscovery).where(
                ShadowAIDiscovery.tenant_id == tenant_id
            )
            if status:
                query = query.where(ShadowAIDiscovery.status == status)
            if risk_level:
                query = query.where(ShadowAIDiscovery.risk_level == risk_level)

            count_result = await session.execute(
                select(func.count()).select_from(query.subquery())
            )
            total: int = count_result.scalar_one()

            offset = (page - 1) * page_size
            result = await session.execute(
                query.order_by(ShadowAIDiscovery.created_at.desc())
                .offset(offset)
                .limit(page_size)
            )
            return list(result.scalars().all()), total

    async def update_status(
        self,
        discovery_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: str,
        dismissed_reason: str | None,
    ) -> ShadowAIDiscovery:
        """Update the status of a discovery.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            status: New status value.
            dismissed_reason: Reason if status is dismissed.

        Returns:
            Updated ShadowAIDiscovery.
        """
        async with get_db_session(tenant_id) as session:
            values: dict[str, Any] = {
                "status": status,
                "updated_at": datetime.now(tz=timezone.utc),
            }
            if dismissed_reason is not None:
                values["dismissed_reason"] = dismissed_reason

            await session.execute(
                update(ShadowAIDiscovery)
                .where(ShadowAIDiscovery.id == discovery_id)
                .values(**values)
            )
            await session.flush()

            result = await session.execute(
                select(ShadowAIDiscovery).where(ShadowAIDiscovery.id == discovery_id)
            )
            return result.scalar_one()

    async def update_risk_assessment(
        self,
        discovery_id: uuid.UUID,
        tenant_id: uuid.UUID,
        risk_score: float,
        risk_level: str,
        data_sensitivity: str,
        compliance_exposure: list[str],
        risk_details: dict[str, Any],
    ) -> ShadowAIDiscovery:
        """Persist risk assessment results on a discovery.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            risk_score: Composite risk score (0.0–1.0).
            risk_level: Severity string.
            data_sensitivity: Estimated data sensitivity category.
            compliance_exposure: List of compliance frameworks at risk.
            risk_details: Detailed breakdown from RiskAssessorService.

        Returns:
            Updated ShadowAIDiscovery with risk data.
        """
        async with get_db_session(tenant_id) as session:
            await session.execute(
                update(ShadowAIDiscovery)
                .where(ShadowAIDiscovery.id == discovery_id)
                .values(
                    risk_score=risk_score,
                    risk_level=risk_level,
                    data_sensitivity=data_sensitivity,
                    compliance_exposure=compliance_exposure,
                    risk_details=risk_details,
                    updated_at=datetime.now(tz=timezone.utc),
                )
            )
            await session.flush()

            result = await session.execute(
                select(ShadowAIDiscovery).where(ShadowAIDiscovery.id == discovery_id)
            )
            return result.scalar_one()

    async def find_existing(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        detected_user_id: uuid.UUID | None,
    ) -> ShadowAIDiscovery | None:
        """Find an existing discovery for the same tool and user.

        Args:
            tenant_id: Owning tenant UUID.
            tool_name: AI tool name.
            detected_user_id: Employee UUID (or None for unknown user).

        Returns:
            Existing ShadowAIDiscovery or None if first detection.
        """
        async with get_db_session(tenant_id) as session:
            query = select(ShadowAIDiscovery).where(
                ShadowAIDiscovery.tenant_id == tenant_id,
                ShadowAIDiscovery.tool_name == tool_name,
            )
            if detected_user_id is not None:
                query = query.where(ShadowAIDiscovery.detected_user_id == detected_user_id)
            else:
                query = query.where(ShadowAIDiscovery.detected_user_id.is_(None))

            result = await session.execute(query.limit(1))
            return result.scalar_one_or_none()

    async def increment_request_count(
        self,
        discovery_id: uuid.UUID,
        tenant_id: uuid.UUID,
        request_count_delta: int,
        estimated_volume_kb_delta: int,
        last_seen_at: datetime,
    ) -> ShadowAIDiscovery:
        """Increment request count and data volume on re-detection.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            request_count_delta: Number of new requests detected.
            estimated_volume_kb_delta: Additional estimated data volume in KB.
            last_seen_at: Timestamp of the latest detection.

        Returns:
            Updated ShadowAIDiscovery with incremented counters.
        """
        async with get_db_session(tenant_id) as session:
            await session.execute(
                update(ShadowAIDiscovery)
                .where(ShadowAIDiscovery.id == discovery_id)
                .values(
                    request_count=ShadowAIDiscovery.request_count + request_count_delta,
                    estimated_data_volume_kb=(
                        ShadowAIDiscovery.estimated_data_volume_kb + estimated_volume_kb_delta
                    ),
                    last_seen_at=last_seen_at,
                    updated_at=datetime.now(tz=timezone.utc),
                )
            )
            await session.flush()

            result = await session.execute(
                select(ShadowAIDiscovery).where(ShadowAIDiscovery.id == discovery_id)
            )
            return result.scalar_one()


class MigrationRepository(BaseRepository[MigrationPlan], IMigrationRepository):
    """Repository for MigrationPlan persistence."""

    model_class = MigrationPlan

    async def create(
        self,
        tenant_id: uuid.UUID,
        discovery_id: uuid.UUID,
        employee_id: uuid.UUID,
        shadow_tool_name: str,
        governed_tool_name: str,
        governed_model_id: uuid.UUID | None,
        migration_steps: list[dict[str, Any]],
        expires_at: datetime,
    ) -> MigrationPlan:
        """Create a new migration plan.

        Args:
            tenant_id: Owning tenant UUID.
            discovery_id: Parent shadow AI discovery UUID.
            employee_id: Employee being migrated.
            shadow_tool_name: Name of the unauthorized tool.
            governed_tool_name: Name of the governed alternative.
            governed_model_id: Optional model registry UUID.
            migration_steps: Ordered list of steps with completion status.
            expires_at: UTC expiry timestamp.

        Returns:
            Newly created MigrationPlan in pending status.
        """
        async with get_db_session(tenant_id) as session:
            plan = MigrationPlan(
                tenant_id=tenant_id,
                discovery_id=discovery_id,
                employee_id=employee_id,
                shadow_tool_name=shadow_tool_name,
                governed_tool_name=governed_tool_name,
                governed_model_id=governed_model_id,
                migration_steps=migration_steps,
                expires_at=expires_at,
                status="pending",
            )
            session.add(plan)
            await session.flush()
            await session.refresh(plan)
            return plan

    async def get_by_id(
        self, plan_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> MigrationPlan | None:
        """Retrieve a migration plan by UUID.

        Args:
            plan_id: MigrationPlan UUID.
            tenant_id: Requesting tenant.

        Returns:
            MigrationPlan or None if not found.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(MigrationPlan).where(
                    MigrationPlan.id == plan_id,
                    MigrationPlan.tenant_id == tenant_id,
                )
            )
            return result.scalar_one_or_none()

    async def list_by_discovery(
        self, discovery_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[MigrationPlan]:
        """List all migration plans for a discovery.

        Args:
            discovery_id: Parent discovery UUID.
            tenant_id: Requesting tenant.

        Returns:
            List of MigrationPlan instances.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(MigrationPlan).where(
                    MigrationPlan.discovery_id == discovery_id,
                    MigrationPlan.tenant_id == tenant_id,
                ).order_by(MigrationPlan.created_at.desc())
            )
            return list(result.scalars().all())

    async def update_status(
        self,
        plan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: str,
        completed_at: datetime | None,
        notes: str | None,
    ) -> MigrationPlan:
        """Update the status of a migration plan.

        Args:
            plan_id: MigrationPlan UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            status: New status value.
            completed_at: Optional completion timestamp.
            notes: Optional free-text notes.

        Returns:
            Updated MigrationPlan.
        """
        async with get_db_session(tenant_id) as session:
            values: dict[str, Any] = {
                "status": status,
                "updated_at": datetime.now(tz=timezone.utc),
            }
            if completed_at is not None:
                values["completed_at"] = completed_at
            if notes is not None:
                values["notes"] = notes

            await session.execute(
                update(MigrationPlan)
                .where(MigrationPlan.id == plan_id)
                .values(**values)
            )
            await session.flush()

            result = await session.execute(
                select(MigrationPlan).where(MigrationPlan.id == plan_id)
            )
            return result.scalar_one()

    async def set_approval_workflow_id(
        self,
        plan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        approval_workflow_id: uuid.UUID,
    ) -> None:
        """Set the approval workflow ID after migration approval is initiated.

        Args:
            plan_id: MigrationPlan UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            approval_workflow_id: Approval workflow UUID from aumos-approval-workflow.
        """
        async with get_db_session(tenant_id) as session:
            await session.execute(
                update(MigrationPlan)
                .where(MigrationPlan.id == plan_id)
                .values(
                    approval_workflow_id=approval_workflow_id,
                    updated_at=datetime.now(tz=timezone.utc),
                )
            )


class ScanResultRepository(BaseRepository[ScanResult], IScanResultRepository):
    """Repository for ScanResult persistence."""

    model_class = ScanResult

    async def create(
        self,
        tenant_id: uuid.UUID,
        scan_type: str,
        scan_parameters: dict[str, Any],
    ) -> ScanResult:
        """Create a scan result record to track a scan execution.

        Args:
            tenant_id: Owning tenant UUID.
            scan_type: scheduled | manual | triggered.
            scan_parameters: Parameters for this scan execution.

        Returns:
            Newly created ScanResult in running status.
        """
        now = datetime.now(tz=timezone.utc)
        async with get_db_session(tenant_id) as session:
            scan = ScanResult(
                tenant_id=tenant_id,
                scan_type=scan_type,
                status="running",
                started_at=now,
                scan_parameters=scan_parameters,
            )
            session.add(scan)
            await session.flush()
            await session.refresh(scan)
            return scan

    async def complete(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        new_discoveries_count: int,
        total_endpoints_checked: int,
        duration_seconds: int,
    ) -> ScanResult:
        """Mark a scan as completed with result statistics.

        Args:
            scan_id: ScanResult UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            new_discoveries_count: Number of new discoveries found.
            total_endpoints_checked: Total endpoints scanned.
            duration_seconds: Scan duration in seconds.

        Returns:
            Updated ScanResult with status=completed.
        """
        async with get_db_session(tenant_id) as session:
            now = datetime.now(tz=timezone.utc)
            await session.execute(
                update(ScanResult)
                .where(ScanResult.id == scan_id)
                .values(
                    status="completed",
                    completed_at=now,
                    new_discoveries_count=new_discoveries_count,
                    total_endpoints_checked=total_endpoints_checked,
                    duration_seconds=duration_seconds,
                    updated_at=now,
                )
            )
            await session.flush()

            result = await session.execute(
                select(ScanResult).where(ScanResult.id == scan_id)
            )
            return result.scalar_one()

    async def fail(
        self,
        scan_id: uuid.UUID,
        tenant_id: uuid.UUID,
        error_message: str,
    ) -> ScanResult:
        """Mark a scan as failed with an error message.

        Args:
            scan_id: ScanResult UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            error_message: Error detail.

        Returns:
            Updated ScanResult with status=failed.
        """
        async with get_db_session(tenant_id) as session:
            now = datetime.now(tz=timezone.utc)
            await session.execute(
                update(ScanResult)
                .where(ScanResult.id == scan_id)
                .values(
                    status="failed",
                    completed_at=now,
                    error_message=error_message,
                    updated_at=now,
                )
            )
            await session.flush()

            result = await session.execute(
                select(ScanResult).where(ScanResult.id == scan_id)
            )
            return result.scalar_one()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[ScanResult], int]:
        """List scan results for a tenant with pagination.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.

        Returns:
            Tuple of (scan_results, total_count).
        """
        async with get_db_session(tenant_id) as session:
            query = select(ScanResult).where(ScanResult.tenant_id == tenant_id)

            count_result = await session.execute(
                select(func.count()).select_from(query.subquery())
            )
            total: int = count_result.scalar_one()

            offset = (page - 1) * page_size
            result = await session.execute(
                query.order_by(ScanResult.created_at.desc())
                .offset(offset)
                .limit(page_size)
            )
            return list(result.scalars().all()), total


class UsageMetricRepository(BaseRepository[UsageMetric], IUsageMetricRepository):
    """Repository for UsageMetric persistence and aggregation."""

    model_class = UsageMetric

    async def upsert_daily(
        self,
        tenant_id: uuid.UUID,
        period_start: datetime,
        period_end: datetime,
        metrics: dict[str, Any],
    ) -> UsageMetric:
        """Upsert daily usage metrics for a tenant.

        Args:
            tenant_id: Owning tenant UUID.
            period_start: Start of the daily period (UTC).
            period_end: End of the daily period (UTC).
            metrics: Metric values to set/update.

        Returns:
            Upserted UsageMetric for the period.
        """
        async with get_db_session(tenant_id) as session:
            existing_result = await session.execute(
                select(UsageMetric).where(
                    UsageMetric.tenant_id == tenant_id,
                    UsageMetric.period_start == period_start,
                    UsageMetric.period_type == "daily",
                )
            )
            existing = existing_result.scalar_one_or_none()

            if existing:
                for key, value in metrics.items():
                    if hasattr(existing, key):
                        setattr(existing, key, value)
                existing.updated_at = datetime.now(tz=timezone.utc)
                await session.flush()
                await session.refresh(existing)
                return existing

            metric = UsageMetric(
                tenant_id=tenant_id,
                period_start=period_start,
                period_end=period_end,
                period_type="daily",
                **{k: v for k, v in metrics.items() if hasattr(UsageMetric, k)},
            )
            session.add(metric)
            await session.flush()
            await session.refresh(metric)
            return metric

    async def get_dashboard_stats(
        self,
        tenant_id: uuid.UUID,
        days: int,
    ) -> dict[str, Any]:
        """Retrieve dashboard statistics for the last N days.

        Args:
            tenant_id: Requesting tenant.
            days: Number of days to include in the aggregation.

        Returns:
            Dict with totals, trends, top tools, and breach cost estimates.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(
                    func.sum(UsageMetric.total_discoveries).label("total_discoveries"),
                    func.sum(UsageMetric.active_users).label("active_users"),
                    func.sum(UsageMetric.critical_count).label("critical_count"),
                    func.sum(UsageMetric.high_count).label("high_count"),
                    func.sum(UsageMetric.medium_count).label("medium_count"),
                    func.sum(UsageMetric.low_count).label("low_count"),
                    func.sum(UsageMetric.migrations_started).label("migrations_started"),
                    func.sum(UsageMetric.migrations_completed).label("migrations_completed"),
                    func.max(UsageMetric.estimated_breach_cost_usd).label("estimated_breach_cost_usd"),
                ).where(
                    UsageMetric.tenant_id == tenant_id,
                    UsageMetric.period_type == "daily",
                    UsageMetric.is_active.is_(True),
                )
            )
            row = result.one_or_none()

            return {
                "total_discoveries": int(row.total_discoveries or 0),
                "active_users": int(row.active_users or 0),
                "critical_count": int(row.critical_count or 0),
                "high_count": int(row.high_count or 0),
                "medium_count": int(row.medium_count or 0),
                "low_count": int(row.low_count or 0),
                "migrations_started": int(row.migrations_started or 0),
                "migrations_completed": int(row.migrations_completed or 0),
                "estimated_breach_cost_usd": float(row.estimated_breach_cost_usd or 0.0),
                "top_tools": [],
                "trend": [],
            }
