"""Repository implementations for P0.3 Shadow AI Detection and Amnesty models.

Concrete SQLAlchemy repository classes for:
  - ShadowDetectionRepository: CRUD and filtered queries for ShadowAIDetection
  - MigrationProposalRepository: CRUD for ShadowMigrationProposal
  - AmnestyProgramRepository: Lifecycle management for AmnestyProgram
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.database import get_db_session
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.core.models.shadow_detection import (
    AmnestyProgram,
    ShadowAIDetection,
    ShadowMigrationProposal,
)

logger = get_logger(__name__)


class ShadowDetectionRepository:
    """Repository for ShadowAIDetection persistence and filtered queries.

    All queries are tenant-scoped to enforce row-level security.
    """

    async def create(self, detection: ShadowAIDetection) -> ShadowAIDetection:
        """Persist a new ShadowAIDetection record.

        Args:
            detection: Pre-populated ShadowAIDetection instance (id already set).

        Returns:
            Persisted ShadowAIDetection after flush.
        """
        async with get_db_session(detection.tenant_id) as session:
            session.add(detection)
            await session.flush()
            await session.refresh(detection)
            return detection

    async def bulk_create(
        self, detections: list[ShadowAIDetection]
    ) -> list[ShadowAIDetection]:
        """Persist multiple ShadowAIDetection records in a single transaction.

        Args:
            detections: List of pre-populated ShadowAIDetection instances.

        Returns:
            List of persisted instances.
        """
        if not detections:
            return []

        tenant_id = detections[0].tenant_id
        async with get_db_session(tenant_id) as session:
            session.add_all(detections)
            await session.flush()
            for detection in detections:
                await session.refresh(detection)
            return detections

    async def get_by_id(
        self, detection_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> ShadowAIDetection | None:
        """Retrieve a detection by UUID within a tenant.

        Args:
            detection_id: Detection UUID.
            tenant_id: Requesting tenant for RLS enforcement.

        Returns:
            ShadowAIDetection or None if not found.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(ShadowAIDetection).where(
                    ShadowAIDetection.id == detection_id,
                    ShadowAIDetection.tenant_id == tenant_id,
                )
            )
            return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
        severity: str | None = None,
        status: str | None = None,
        provider: str | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> tuple[list[ShadowAIDetection], int]:
        """List detections for a tenant with optional filters and pagination.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.
            severity: Optional sensitivity level filter (low/medium/high/critical).
            status: Optional status filter.
            provider: Optional provider identifier filter.
            date_from: Optional start of detection window (UTC).
            date_to: Optional end of detection window (UTC).

        Returns:
            Tuple of (detections, total_count).
        """
        async with get_db_session(tenant_id) as session:
            query = select(ShadowAIDetection).where(
                ShadowAIDetection.tenant_id == tenant_id
            )

            if severity:
                query = query.where(
                    ShadowAIDetection.estimated_data_sensitivity == severity
                )
            if status:
                query = query.where(ShadowAIDetection.status == status)
            if provider:
                query = query.where(ShadowAIDetection.provider == provider)
            if date_from:
                query = query.where(ShadowAIDetection.created_at >= date_from)
            if date_to:
                query = query.where(ShadowAIDetection.created_at <= date_to)

            count_result = await session.execute(
                select(func.count()).select_from(query.subquery())
            )
            total: int = count_result.scalar_one()

            offset = (page - 1) * page_size
            result = await session.execute(
                query.order_by(ShadowAIDetection.created_at.desc())
                .offset(offset)
                .limit(page_size)
            )
            return list(result.scalars().all()), total

    async def update_status(
        self,
        detection_id: uuid.UUID,
        status: str,
        tenant_id: uuid.UUID,
    ) -> ShadowAIDetection:
        """Update the lifecycle status of a detection.

        Args:
            detection_id: Detection UUID.
            status: New status value.
            tenant_id: Requesting tenant for RLS.

        Returns:
            Updated ShadowAIDetection.
        """
        async with get_db_session(tenant_id) as session:
            await session.execute(
                update(ShadowAIDetection)
                .where(
                    ShadowAIDetection.id == detection_id,
                    ShadowAIDetection.tenant_id == tenant_id,
                )
                .values(
                    status=status,
                    updated_at=datetime.now(tz=timezone.utc),
                )
            )
            await session.flush()

            result = await session.execute(
                select(ShadowAIDetection).where(
                    ShadowAIDetection.id == detection_id
                )
            )
            return result.scalar_one()


class MigrationProposalRepository:
    """Repository for ShadowMigrationProposal persistence."""

    async def create(
        self, proposal: ShadowMigrationProposal
    ) -> ShadowMigrationProposal:
        """Persist a new ShadowMigrationProposal.

        Args:
            proposal: Pre-populated ShadowMigrationProposal instance.

        Returns:
            Persisted proposal after flush.
        """
        async with get_db_session(proposal.tenant_id) as session:
            session.add(proposal)
            await session.flush()
            await session.refresh(proposal)
            return proposal

    async def get_by_id(
        self, proposal_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> ShadowMigrationProposal | None:
        """Retrieve a proposal by UUID.

        Args:
            proposal_id: Proposal UUID.
            tenant_id: Requesting tenant.

        Returns:
            ShadowMigrationProposal or None.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(ShadowMigrationProposal).where(
                    ShadowMigrationProposal.id == proposal_id,
                    ShadowMigrationProposal.tenant_id == tenant_id,
                )
            )
            return result.scalar_one_or_none()

    async def list_by_detection(
        self,
        detection_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> list[ShadowMigrationProposal]:
        """List all proposals for a given detection.

        Args:
            detection_id: Parent detection UUID.
            tenant_id: Requesting tenant.

        Returns:
            List of ShadowMigrationProposal instances.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(ShadowMigrationProposal).where(
                    ShadowMigrationProposal.detection_id == detection_id,
                    ShadowMigrationProposal.tenant_id == tenant_id,
                ).order_by(ShadowMigrationProposal.created_at.desc())
            )
            return list(result.scalars().all())


class AmnestyProgramRepository:
    """Repository for AmnestyProgram lifecycle management."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        notification_message: str,
        grace_period_days: int,
        grace_period_expires_at: datetime,
        status: str = "active",
        initiated_by: uuid.UUID | None = None,
        affected_user_count: int = 0,
    ) -> AmnestyProgram:
        """Create a new AmnestyProgram record.

        Args:
            tenant_id: Owning tenant UUID.
            notification_message: User-facing notification message.
            grace_period_days: Duration of grace period in days.
            grace_period_expires_at: UTC expiry timestamp.
            status: Initial lifecycle status (default "active").
            initiated_by: Optional UUID of initiating admin.
            affected_user_count: Number of affected users at initiation.

        Returns:
            Newly created AmnestyProgram.
        """
        async with get_db_session(tenant_id) as session:
            program = AmnestyProgram(
                tenant_id=tenant_id,
                notification_message=notification_message,
                grace_period_days=grace_period_days,
                grace_period_expires_at=grace_period_expires_at,
                status=status,
                initiated_by=initiated_by,
                affected_user_count=affected_user_count,
            )
            session.add(program)
            await session.flush()
            await session.refresh(program)
            return program

    async def get_active_for_tenant(
        self, tenant_id: uuid.UUID
    ) -> AmnestyProgram | None:
        """Retrieve the active or grace-period amnesty program for a tenant.

        Returns None if no program exists or all programs are in terminal status
        (enforcing, cancelled).

        Args:
            tenant_id: Requesting tenant.

        Returns:
            Active AmnestyProgram or None.
        """
        async with get_db_session(tenant_id) as session:
            result = await session.execute(
                select(AmnestyProgram).where(
                    AmnestyProgram.tenant_id == tenant_id,
                    AmnestyProgram.status.in_({"active", "grace_period", "enforcing"}),
                ).order_by(AmnestyProgram.created_at.desc()).limit(1)
            )
            return result.scalar_one_or_none()

    async def update_status(
        self,
        program_id: uuid.UUID,
        tenant_id: uuid.UUID,
        status: str,
        enforcement_started_at: datetime | None = None,
        cancellation_reason: str | None = None,
    ) -> AmnestyProgram:
        """Update the lifecycle status of an amnesty program.

        Args:
            program_id: AmnestyProgram UUID.
            tenant_id: Owning tenant UUID for RLS enforcement.
            status: New status value.
            enforcement_started_at: Timestamp if transitioning to "enforcing".
            cancellation_reason: Reason if status is "cancelled".

        Returns:
            Updated AmnestyProgram.
        """
        async with get_db_session(tenant_id) as session:
            values: dict[str, Any] = {
                "status": status,
                "updated_at": datetime.now(tz=timezone.utc),
            }
            if enforcement_started_at is not None:
                values["enforcement_started_at"] = enforcement_started_at
            if cancellation_reason is not None:
                values["cancellation_reason"] = cancellation_reason

            await session.execute(
                update(AmnestyProgram)
                .where(AmnestyProgram.id == program_id)
                .values(**values)
            )
            await session.flush()

            result = await session.execute(
                select(AmnestyProgram).where(AmnestyProgram.id == program_id)
            )
            return result.scalar_one()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[AmnestyProgram], int]:
        """List amnesty programs for a tenant with pagination.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.

        Returns:
            Tuple of (programs, total_count).
        """
        async with get_db_session(tenant_id) as session:
            query = select(AmnestyProgram).where(AmnestyProgram.tenant_id == tenant_id)

            count_result = await session.execute(
                select(func.count()).select_from(query.subquery())
            )
            total: int = count_result.scalar_one()

            offset = (page - 1) * page_size
            result = await session.execute(
                query.order_by(AmnestyProgram.created_at.desc())
                .offset(offset)
                .limit(page_size)
            )
            return list(result.scalars().all()), total
