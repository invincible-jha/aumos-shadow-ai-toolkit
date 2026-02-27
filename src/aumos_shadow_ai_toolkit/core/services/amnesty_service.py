"""Amnesty Program Service — Shadow AI Amnesty workflow management.

The Shadow AI Amnesty Program provides a structured path for organizations
to surface and migrate unauthorized AI tool usage without immediate punitive
enforcement. The workflow:

  1. Tenant admin initiates amnesty with a grace period
  2. System identifies all shadow AI usage for that tenant
  3. Affected users are notified with migration proposals
  4. During grace period: usage is tracked but not blocked
  5. After grace period: governed-only enforcement activates

Status lifecycle: active -> grace_period -> enforcing | cancelled
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.core.models.shadow_detection import AmnestyProgram

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Dataclass response types
# ---------------------------------------------------------------------------


@dataclass
class AffectedUser:
    """A user with detected shadow AI usage, eligible for amnesty program.

    Attributes:
        user_id: UUID of the affected employee (may be None if unidentified).
        detection_count: Number of shadow AI detections linked to this user.
        providers: Set of AI providers the user has accessed.
        highest_risk_score: Maximum compliance risk score across their detections.
    """

    user_id: uuid.UUID | None
    detection_count: int
    providers: set[str]
    highest_risk_score: float


@dataclass
class AmnestyStatus:
    """Current status snapshot of a tenant's amnesty program.

    Attributes:
        tenant_id: The tenant this status applies to.
        program_id: UUID of the active amnesty program, or None if none exists.
        status: Current lifecycle status string.
        grace_period_days: Configured grace period length in days.
        grace_period_expires_at: When the grace period ends, or None.
        affected_user_count: Users with shadow AI detections.
        is_active: Whether an amnesty program is currently running.
        enforcement_started_at: When enforcement began, or None.
    """

    tenant_id: uuid.UUID
    program_id: uuid.UUID | None
    status: str
    grace_period_days: int
    grace_period_expires_at: datetime | None
    affected_user_count: int
    is_active: bool
    enforcement_started_at: datetime | None


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class AmnestyProgramService:
    """Manages the Shadow AI Amnesty Program workflow for tenants.

    Orchestrates the full lifecycle of amnesty programs: initiation, user
    notification tracking, grace period management, and enforcement transition.
    All state is persisted via the provided amnesty repository.
    """

    def __init__(
        self,
        amnesty_repository: Any,
        detection_repository: Any,
    ) -> None:
        """Initialise with repository dependencies.

        Args:
            amnesty_repository: Repository for AmnestyProgram persistence.
                Must implement create(), get_active_for_tenant(), update_status(),
                and list_by_tenant() methods.
            detection_repository: Repository for ShadowAIDetection queries.
                Must implement list_by_tenant() returning (detections, total).
        """
        self._amnesty_repo = amnesty_repository
        self._detection_repo = detection_repository

    async def initiate_amnesty(
        self,
        tenant_id: uuid.UUID,
        message: str,
        grace_period_days: int,
        initiated_by: uuid.UUID | None = None,
    ) -> AmnestyProgram:
        """Start an amnesty program for a tenant.

        Creates a new AmnestyProgram record with the configured grace period.
        The grace period begins immediately on initiation.

        Args:
            tenant_id: UUID of the tenant initiating the amnesty.
            message: Notification message to send to affected users.
            grace_period_days: Number of days before enforcement activates.
            initiated_by: Optional UUID of the admin initiating the program.

        Returns:
            Newly created AmnestyProgram in "active" status.
        """
        now = datetime.now(tz=timezone.utc)
        grace_expiry = now + timedelta(days=grace_period_days)

        program = await self._amnesty_repo.create(
            tenant_id=tenant_id,
            notification_message=message,
            grace_period_days=grace_period_days,
            grace_period_expires_at=grace_expiry,
            status="active",
            initiated_by=initiated_by,
        )

        logger.info(
            "Shadow AI amnesty program initiated",
            tenant_id=str(tenant_id),
            program_id=str(program.id),
            grace_period_days=grace_period_days,
            grace_expires_at=grace_expiry.isoformat(),
        )

        return program

    async def get_affected_users(self, tenant_id: uuid.UUID) -> list[AffectedUser]:
        """List all users with shadow AI detections for a tenant.

        Aggregates detections by detected user ID (or None for unidentified).
        Returns a ranked list ordered by highest risk score descending.

        Args:
            tenant_id: UUID of the tenant to query.

        Returns:
            List of AffectedUser instances, ordered by highest_risk_score desc.
        """
        detections, _total = await self._detection_repo.list_by_tenant(
            tenant_id=tenant_id,
            page=1,
            page_size=10_000,
            status=None,
        )

        # Aggregate by detected user — detections from the sat_shadow_detections table
        # may not have a detected_user_id (network-level detection); group those together
        user_aggregates: dict[uuid.UUID | None, dict[str, Any]] = {}

        for detection in detections:
            # ShadowAIDetection does not carry detected_user_id (that's on the older
            # ShadowAIDiscovery). Group all detections by source_ip as a proxy.
            # When integrating with IAM, source_ip can be correlated to a user.
            key: uuid.UUID | None = None  # Network-level; user attribution requires IAM

            if key not in user_aggregates:
                user_aggregates[key] = {
                    "detection_count": 0,
                    "providers": set(),
                    "risk_scores": [],
                }

            agg = user_aggregates[key]
            agg["detection_count"] += 1
            agg["providers"].add(detection.provider)
            agg["risk_scores"].append(float(detection.compliance_risk_score))

        affected_users = [
            AffectedUser(
                user_id=user_id,
                detection_count=agg["detection_count"],
                providers=agg["providers"],
                highest_risk_score=max(agg["risk_scores"], default=0.0),
            )
            for user_id, agg in user_aggregates.items()
        ]

        # Sort descending by highest risk score
        affected_users.sort(key=lambda u: u.highest_risk_score, reverse=True)

        logger.info(
            "Affected users retrieved for amnesty program",
            tenant_id=str(tenant_id),
            affected_user_count=len(affected_users),
        )

        return affected_users

    async def get_amnesty_status(self, tenant_id: uuid.UUID) -> AmnestyStatus:
        """Return the current amnesty program status for a tenant.

        Automatically transitions programs from "active" to "grace_period" or
        from "grace_period" to "enforcing" based on the grace_period_expires_at
        timestamp — without requiring external scheduler calls.

        Args:
            tenant_id: UUID of the tenant to check.

        Returns:
            AmnestyStatus describing current program state.
        """
        program: AmnestyProgram | None = await self._amnesty_repo.get_active_for_tenant(
            tenant_id=tenant_id
        )

        if program is None:
            return AmnestyStatus(
                tenant_id=tenant_id,
                program_id=None,
                status="none",
                grace_period_days=0,
                grace_period_expires_at=None,
                affected_user_count=0,
                is_active=False,
                enforcement_started_at=None,
            )

        now = datetime.now(tz=timezone.utc)
        current_status = program.status

        # Auto-transition: active -> grace_period (immediately on initiation — they're
        # the same phase semantically; "active" means grace period is running)
        # Auto-transition: grace_period -> enforcing once expiry passes
        if (
            current_status in {"active", "grace_period"}
            and program.grace_period_expires_at is not None
            and now >= program.grace_period_expires_at
        ):
            current_status = "enforcing"
            await self._amnesty_repo.update_status(
                program_id=program.id,
                status="enforcing",
                enforcement_started_at=now,
            )

            logger.info(
                "Amnesty program transitioned to enforcing",
                tenant_id=str(tenant_id),
                program_id=str(program.id),
                enforcement_started_at=now.isoformat(),
            )

        return AmnestyStatus(
            tenant_id=tenant_id,
            program_id=program.id,
            status=current_status,
            grace_period_days=program.grace_period_days,
            grace_period_expires_at=program.grace_period_expires_at,
            affected_user_count=program.affected_user_count,
            is_active=current_status in {"active", "grace_period"},
            enforcement_started_at=program.enforcement_started_at,
        )

    async def cancel_amnesty(
        self,
        tenant_id: uuid.UUID,
        reason: str | None = None,
    ) -> AmnestyProgram | None:
        """Cancel an active amnesty program for a tenant.

        Args:
            tenant_id: UUID of the tenant.
            reason: Optional cancellation reason.

        Returns:
            Updated AmnestyProgram with status "cancelled", or None if no active program.
        """
        program = await self._amnesty_repo.get_active_for_tenant(tenant_id=tenant_id)

        if program is None:
            logger.warning(
                "Attempted to cancel amnesty program that does not exist",
                tenant_id=str(tenant_id),
            )
            return None

        updated = await self._amnesty_repo.update_status(
            program_id=program.id,
            status="cancelled",
            cancellation_reason=reason,
        )

        logger.info(
            "Amnesty program cancelled",
            tenant_id=str(tenant_id),
            program_id=str(program.id),
            reason=reason,
        )

        return updated
