"""FastAPI routes for P0.3 Shadow AI Detection and Amnesty Baseline.

All routes are prefixed with /api/v1 and tagged "shadow-ai-detection".
Routes delegate entirely to service layer — no business logic here.

Available endpoints:
  GET  /api/v1/shadow-ai/detections
  POST /api/v1/shadow-ai/detections/{id}/propose-migration
  POST /api/v1/shadow-ai/amnesty-program/initiate
  GET  /api/v1/shadow-ai/amnesty-program/status
  POST /api/v1/shadow-ai/analyze
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from aumos_common.auth import TenantContext, get_current_tenant
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.adapters.shadow_repositories import (
    AmnestyProgramRepository,
    MigrationProposalRepository,
    ShadowDetectionRepository,
)
from aumos_shadow_ai_toolkit.api.schemas_shadow import (
    AmnestyInitiateRequest,
    AmnestyInitiateResponse,
    AmnestyStatusResponse,
    AnalyzeNetworkLogsResponse,
    DetectionListResponse,
    MigrationProposalResponse,
    MigrationSummaryResponse,
    NetworkLogSubmission,
    ProposeMigrationResponse,
    ShadowAIDetectionResponse,
)
from aumos_shadow_ai_toolkit.core.services.amnesty_service import AmnestyProgramService
from aumos_shadow_ai_toolkit.core.services.detection_service import ShadowAIDetectionService
from aumos_shadow_ai_toolkit.core.services.migration_service import MigrationProposalService

logger = get_logger(__name__)

router = APIRouter(tags=["shadow-ai-detection"])


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------


def _get_detection_repo() -> ShadowDetectionRepository:
    """Dependency factory for ShadowDetectionRepository.

    Returns:
        ShadowDetectionRepository instance.
    """
    return ShadowDetectionRepository()


def _get_proposal_repo() -> MigrationProposalRepository:
    """Dependency factory for MigrationProposalRepository.

    Returns:
        MigrationProposalRepository instance.
    """
    return MigrationProposalRepository()


def _get_amnesty_repo() -> AmnestyProgramRepository:
    """Dependency factory for AmnestyProgramRepository.

    Returns:
        AmnestyProgramRepository instance.
    """
    return AmnestyProgramRepository()


# ---------------------------------------------------------------------------
# Detection listing
# ---------------------------------------------------------------------------


@router.get(
    "/shadow-ai/detections",
    response_model=DetectionListResponse,
    summary="List shadow AI detections",
    description=(
        "List all shadow AI detection events for the current tenant with optional "
        "filtering by severity, status, provider, and date range."
    ),
)
async def list_detections(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    repo: Annotated[ShadowDetectionRepository, Depends(_get_detection_repo)],
    severity: Annotated[
        str | None,
        Query(description="Filter by sensitivity: low | medium | high | critical"),
    ] = None,
    status_filter: Annotated[
        str | None,
        Query(alias="status", description="Filter by detection status"),
    ] = None,
    provider: Annotated[
        str | None,
        Query(description="Filter by AI provider identifier (e.g., openai, anthropic)"),
    ] = None,
    date_from: Annotated[
        datetime | None,
        Query(description="Start of detection window (UTC ISO-8601)"),
    ] = None,
    date_to: Annotated[
        datetime | None,
        Query(description="End of detection window (UTC ISO-8601)"),
    ] = None,
    page: Annotated[int, Query(ge=1, description="Page number (1-indexed)")] = 1,
    page_size: Annotated[
        int, Query(ge=1, le=200, description="Results per page (max 200)")
    ] = 20,
) -> DetectionListResponse:
    """List shadow AI detections for the current tenant.

    Args:
        tenant: Authenticated tenant context from JWT.
        repo: ShadowDetectionRepository dependency.
        severity: Optional sensitivity level filter.
        status_filter: Optional lifecycle status filter.
        provider: Optional provider identifier filter.
        date_from: Optional date range start.
        date_to: Optional date range end.
        page: Page number.
        page_size: Results per page.

    Returns:
        DetectionListResponse with pagination metadata.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)
    detections, total = await repo.list_by_tenant(
        tenant_id=tenant_id,
        page=page,
        page_size=page_size,
        severity=severity,
        status=status_filter,
        provider=provider,
        date_from=date_from,
        date_to=date_to,
    )

    total_pages = max(1, (total + page_size - 1) // page_size)

    return DetectionListResponse(
        items=[ShadowAIDetectionResponse.model_validate(d) for d in detections],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


# ---------------------------------------------------------------------------
# Migration proposal generation
# ---------------------------------------------------------------------------


@router.post(
    "/shadow-ai/detections/{detection_id}/propose-migration",
    response_model=ProposeMigrationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose AumOS migration for a detection",
    description=(
        "Generate a migration proposal mapping the detected shadow AI usage pattern "
        "to the most appropriate AumOS governed module with complexity and effort estimates."
    ),
)
async def propose_migration(
    detection_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    detection_repo: Annotated[ShadowDetectionRepository, Depends(_get_detection_repo)],
    proposal_repo: Annotated[MigrationProposalRepository, Depends(_get_proposal_repo)],
) -> ProposeMigrationResponse:
    """Generate and persist a migration proposal for a shadow AI detection.

    Args:
        detection_id: UUID of the detection to propose migration for.
        tenant: Authenticated tenant context from JWT.
        detection_repo: ShadowDetectionRepository dependency.
        proposal_repo: MigrationProposalRepository dependency.

    Returns:
        ProposeMigrationResponse with detection ID and proposal details.

    Raises:
        HTTPException 404: If detection not found for this tenant.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    detection = await detection_repo.get_by_id(detection_id, tenant_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id} not found for this tenant",
        )

    service = MigrationProposalService()
    proposal = await service.generate_proposal(detection)
    saved_proposal = await proposal_repo.create(proposal)

    logger.info(
        "Migration proposal created via API",
        tenant_id=str(tenant_id),
        detection_id=str(detection_id),
        proposal_id=str(saved_proposal.id),
        module=saved_proposal.proposed_aumos_module,
    )

    return ProposeMigrationResponse(
        detection_id=detection_id,
        proposal=MigrationProposalResponse.model_validate(saved_proposal),
    )


# ---------------------------------------------------------------------------
# Amnesty program
# ---------------------------------------------------------------------------


@router.post(
    "/shadow-ai/amnesty-program/initiate",
    response_model=AmnestyInitiateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate Shadow AI Amnesty Program",
    description=(
        "Start an amnesty program for the current tenant. Identifies all shadow AI "
        "users, notifies them with the configured message, and starts the grace period."
    ),
)
async def initiate_amnesty(
    request_body: AmnestyInitiateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    detection_repo: Annotated[ShadowDetectionRepository, Depends(_get_detection_repo)],
    amnesty_repo: Annotated[AmnestyProgramRepository, Depends(_get_amnesty_repo)],
) -> AmnestyInitiateResponse:
    """Initiate the Shadow AI Amnesty Program for a tenant.

    Args:
        request_body: Amnesty initiation parameters.
        tenant: Authenticated tenant context from JWT.
        detection_repo: ShadowDetectionRepository for counting affected users.
        amnesty_repo: AmnestyProgramRepository dependency.

    Returns:
        AmnestyInitiateResponse with program details and affected user count.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    service = AmnestyProgramService(
        amnesty_repository=amnesty_repo,
        detection_repository=detection_repo,
    )

    # Count affected users before initiating
    affected_users = await service.get_affected_users(tenant_id)

    # Count pending migration proposals needed
    _detections, total_detections = await detection_repo.list_by_tenant(
        tenant_id=tenant_id,
        page=1,
        page_size=1,
        status="detected",
    )

    program = await service.initiate_amnesty(
        tenant_id=tenant_id,
        message=request_body.notification_message,
        grace_period_days=request_body.grace_period_days,
    )

    # Update affected user count on the program record
    if program.affected_user_count == 0 and affected_users:
        await amnesty_repo.update_status(
            program_id=program.id,
            tenant_id=tenant_id,
            status=program.status,
        )

    return AmnestyInitiateResponse(
        program_id=program.id,
        tenant_id=program.tenant_id,
        status=program.status,
        affected_users_count=len(affected_users),
        estimated_migrations_count=total_detections,
        grace_period_days=program.grace_period_days,
        grace_period_expires_at=program.grace_period_expires_at,
        created_at=program.created_at,
    )


@router.get(
    "/shadow-ai/amnesty-program/status",
    response_model=AmnestyStatusResponse,
    summary="Get amnesty program status",
    description="Retrieve the current status of the Shadow AI Amnesty Program for the authenticated tenant.",
)
async def get_amnesty_status(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    detection_repo: Annotated[ShadowDetectionRepository, Depends(_get_detection_repo)],
    amnesty_repo: Annotated[AmnestyProgramRepository, Depends(_get_amnesty_repo)],
) -> AmnestyStatusResponse:
    """Get the current status of an amnesty program for the authenticated tenant.

    Args:
        tenant: Authenticated tenant context from JWT — never from URL path.
        detection_repo: ShadowDetectionRepository dependency.
        amnesty_repo: AmnestyProgramRepository dependency.

    Returns:
        AmnestyStatusResponse with current lifecycle status.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)
    service = AmnestyProgramService(
        amnesty_repository=amnesty_repo,
        detection_repository=detection_repo,
    )

    amnesty_status = await service.get_amnesty_status(tenant_id)

    return AmnestyStatusResponse(
        tenant_id=amnesty_status.tenant_id,
        program_id=amnesty_status.program_id,
        status=amnesty_status.status,
        grace_period_days=amnesty_status.grace_period_days,
        grace_period_expires_at=amnesty_status.grace_period_expires_at,
        affected_user_count=amnesty_status.affected_user_count,
        is_active=amnesty_status.is_active,
        enforcement_started_at=amnesty_status.enforcement_started_at,
    )


# ---------------------------------------------------------------------------
# Network log analysis
# ---------------------------------------------------------------------------


@router.post(
    "/shadow-ai/analyze",
    response_model=AnalyzeNetworkLogsResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze network logs for shadow AI",
    description=(
        "Submit a batch of network log entries for shadow AI analysis. "
        "The engine matches against 100+ known AI provider domains, classifies "
        "data sensitivity, and computes compliance risk scores. "
        "Request/response content is never inspected or stored — metadata only."
    ),
)
async def analyze_network_logs(
    submission: NetworkLogSubmission,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    detection_repo: Annotated[ShadowDetectionRepository, Depends(_get_detection_repo)],
) -> AnalyzeNetworkLogsResponse:
    """Analyze a batch of network logs to detect shadow AI usage.

    The detection pipeline:
    1. Match each log entry destination domain against the AI provider registry
    2. Aggregate entries by domain
    3. Classify data sensitivity from URL path and request size
    4. Compute weighted compliance risk score
    5. Create detection records and persist them
    6. Return summary of findings

    The tenant_id from the request body is ignored — tenant identity is always
    taken from the authenticated JWT to prevent cross-tenant data injection.

    Args:
        submission: Batch of network log entries.
        tenant: Authenticated tenant context from JWT.
        detection_repo: ShadowDetectionRepository for persistence.

    Returns:
        AnalyzeNetworkLogsResponse with detection count and risk summary.
    """
    # Always use the authenticated tenant — never trust a client-supplied tenant_id.
    tenant_id = uuid.UUID(tenant.tenant_id)

    service = ShadowAIDetectionService(tenant_id=tenant_id)
    detections = await service.detect_from_network_log(submission.log_entries)

    if detections:
        await detection_repo.bulk_create(detections)

    providers_detected = list({d.provider for d in detections})
    highest_risk = (
        max(float(d.compliance_risk_score) for d in detections)
        if detections
        else 0.0
    )

    logger.info(
        "Network log analysis complete",
        tenant_id=str(tenant_id),
        log_entries=len(submission.log_entries),
        detections_found=len(detections),
        providers=providers_detected,
        highest_risk_score=highest_risk,
    )

    return AnalyzeNetworkLogsResponse(
        detections_found=len(detections),
        providers_detected=sorted(providers_detected),
        highest_risk_score=Decimal(str(round(highest_risk, 2))),
        detections=[ShadowAIDetectionResponse.model_validate(d) for d in detections],
    )
