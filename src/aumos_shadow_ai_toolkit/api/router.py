"""FastAPI router for the AumOS Shadow AI Toolkit REST API.

All endpoints are prefixed with /api/v1/shadow-ai. Authentication and tenant
extraction are handled by aumos-auth-gateway upstream; tenant_id is available
via JWT or the X-Tenant-ID header.

Business logic is never implemented here — routes delegate entirely to services.
"""

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status  # Request used in service-factory deps

from aumos_common.auth import TenantContext, get_current_tenant
from aumos_common.errors import ConflictError, NotFoundError
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.api.schemas import (
    DashboardResponse,
    DashboardTopTool,
    DashboardTrendPoint,
    DiscoveryListResponse,
    MigrationPlanResponse,
    MigrationStartRequest,
    RiskLevelCounts,
    RiskReportResponse,
    ScanInitiateRequest,
    ScanResultResponse,
    ShadowAIDiscoveryResponse,
    TopRiskEntry,
)
from aumos_shadow_ai_toolkit.core.services import (
    DashboardService,
    DiscoveryService,
    MigrationService,
    RiskAssessorService,
)

logger = get_logger(__name__)

router = APIRouter(tags=["shadow-ai"])


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------


def _get_discovery_service(request: Request) -> DiscoveryService:
    """Retrieve DiscoveryService from app state.

    Args:
        request: FastAPI request with app state populated in lifespan.

    Returns:
        DiscoveryService instance.
    """
    return request.app.state.discovery_service  # type: ignore[no-any-return]


def _get_risk_service(request: Request) -> RiskAssessorService:
    """Retrieve RiskAssessorService from app state.

    Args:
        request: FastAPI request with app state populated in lifespan.

    Returns:
        RiskAssessorService instance.
    """
    return request.app.state.risk_service  # type: ignore[no-any-return]


def _get_migration_service(request: Request) -> MigrationService:
    """Retrieve MigrationService from app state.

    Args:
        request: FastAPI request with app state populated in lifespan.

    Returns:
        MigrationService instance.
    """
    return request.app.state.migration_service  # type: ignore[no-any-return]


def _get_dashboard_service(request: Request) -> DashboardService:
    """Retrieve DashboardService from app state.

    Args:
        request: FastAPI request with app state populated in lifespan.

    Returns:
        DashboardService instance.
    """
    return request.app.state.dashboard_service  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Scan endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/shadow-ai/scan",
    response_model=ScanResultResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate network scan",
    description=(
        "Trigger a network scan to detect unauthorized AI tool usage. "
        "Analyses DNS patterns, TLS SNI, and known API endpoints. "
        "Content is never inspected — metadata only."
    ),
)
async def initiate_scan(
    request_body: ScanInitiateRequest,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    service: DiscoveryService = Depends(_get_discovery_service),
) -> ScanResultResponse:
    """Initiate a network scan for shadow AI tool detection.

    Args:
        request_body: Scan parameters.
        tenant: Authenticated tenant context from JWT.
        service: DiscoveryService dependency.

    Returns:
        ScanResultResponse with the completed scan result.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    try:
        scan = await service.initiate_scan(
            tenant_id=tenant_id,
            scan_type=request_body.scan_type,
        )
    except Exception as exc:
        logger.error("Scan initiation failed", tenant_id=str(tenant_id), error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {exc}",
        ) from exc

    logger.info("Scan initiated via API", tenant_id=str(tenant_id), scan_id=str(scan.id))
    return ScanResultResponse.model_validate(scan)


# ---------------------------------------------------------------------------
# Discovery endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/shadow-ai/discoveries",
    response_model=DiscoveryListResponse,
    summary="List shadow AI discoveries",
    description="List all detected shadow AI tools for the current tenant with pagination.",
)
async def list_discoveries(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    page: int = 1,
    page_size: int = 20,
    status_filter: str | None = None,
    risk_level: str | None = None,
    service: DiscoveryService = Depends(_get_discovery_service),
) -> DiscoveryListResponse:
    """List shadow AI discoveries for the current tenant.

    Args:
        tenant: Authenticated tenant context from JWT.
        page: 1-based page number (default 1).
        page_size: Results per page (default 20, max 100).
        status_filter: Optional status to filter by.
        risk_level: Optional risk level to filter by.
        service: DiscoveryService dependency.

    Returns:
        DiscoveryListResponse with pagination metadata.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)
    discoveries, total = await service.list_discoveries(
        tenant_id=tenant_id,
        page=page,
        page_size=min(page_size, 100),
        status=status_filter,
        risk_level=risk_level,
    )

    return DiscoveryListResponse(
        items=[ShadowAIDiscoveryResponse.model_validate(d) for d in discoveries],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/shadow-ai/discoveries/{discovery_id}",
    response_model=ShadowAIDiscoveryResponse,
    summary="Get discovery detail",
    description="Retrieve a single shadow AI discovery with full risk assessment.",
)
async def get_discovery(
    discovery_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    service: DiscoveryService = Depends(_get_discovery_service),
) -> ShadowAIDiscoveryResponse:
    """Retrieve a single shadow AI discovery.

    Args:
        discovery_id: Discovery UUID.
        tenant: Authenticated tenant context from JWT.
        service: DiscoveryService dependency.

    Returns:
        ShadowAIDiscoveryResponse.

    Raises:
        HTTPException 404: If discovery not found.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    try:
        discovery = await service.get_discovery(discovery_id, tenant_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    return ShadowAIDiscoveryResponse.model_validate(discovery)


@router.delete(
    "/shadow-ai/discoveries/{discovery_id}",
    response_model=ShadowAIDiscoveryResponse,
    summary="Dismiss discovery",
    description="Dismiss a shadow AI discovery, removing it from active monitoring.",
)
async def dismiss_discovery(
    discovery_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    reason: str | None = None,
    service: DiscoveryService = Depends(_get_discovery_service),
) -> ShadowAIDiscoveryResponse:
    """Dismiss a shadow AI discovery.

    Args:
        discovery_id: Discovery UUID.
        tenant: Authenticated tenant context from JWT.
        reason: Optional reason for dismissal.
        service: DiscoveryService dependency.

    Returns:
        Updated ShadowAIDiscoveryResponse with status=dismissed.

    Raises:
        HTTPException 404: If discovery not found.
        HTTPException 409: If discovery is already in a terminal state.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    try:
        discovery = await service.dismiss_discovery(discovery_id, tenant_id, reason)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return ShadowAIDiscoveryResponse.model_validate(discovery)


# ---------------------------------------------------------------------------
# Risk report endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/shadow-ai/risk-report",
    response_model=RiskReportResponse,
    summary="Risk assessment report",
    description=(
        "Generate an aggregated risk report showing breach cost exposure "
        "and top-risk discoveries for the current tenant."
    ),
)
async def get_risk_report(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    service: RiskAssessorService = Depends(_get_risk_service),
) -> RiskReportResponse:
    """Generate an aggregated risk report for the current tenant.

    Args:
        tenant: Authenticated tenant context from JWT.
        service: RiskAssessorService dependency.

    Returns:
        RiskReportResponse with breach cost estimates and top risks.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)
    report = await service.get_risk_report(tenant_id)

    by_level_raw: dict[str, int] = report.get("by_risk_level", {})
    top_risks_raw: list[dict[str, object]] = report.get("top_risks", [])

    top_risks = [
        TopRiskEntry(
            discovery_id=uuid.UUID(str(r["discovery_id"])),
            tool_name=str(r["tool_name"]),
            risk_score=float(str(r["risk_score"])),
            risk_level=str(r["risk_level"]),
            compliance_exposure=[str(c) for c in (r.get("compliance_exposure") or [])],
        )
        for r in top_risks_raw
    ]

    return RiskReportResponse(
        total_discoveries=report.get("total_discoveries", 0),
        by_risk_level=RiskLevelCounts(
            critical=by_level_raw.get("critical", 0),
            high=by_level_raw.get("high", 0),
            medium=by_level_raw.get("medium", 0),
            low=by_level_raw.get("low", 0),
            unknown=by_level_raw.get("unknown", 0),
        ),
        estimated_breach_cost_usd=report.get("estimated_breach_cost_usd", 0.0),
        top_risks=top_risks,
        generated_at=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Migration endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/shadow-ai/migrate/{tool_id}",
    response_model=MigrationPlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start migration workflow",
    description=(
        "Initiate a migration workflow to move an employee from a shadow AI tool "
        "to a sanctioned governed alternative."
    ),
)
async def start_migration(
    tool_id: uuid.UUID,
    request_body: MigrationStartRequest,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    service: MigrationService = Depends(_get_migration_service),
) -> MigrationPlanResponse:
    """Start a migration workflow for a shadow AI discovery.

    Args:
        tool_id: Discovery UUID (the shadow AI tool to migrate away from).
        request_body: Migration parameters including governed alternative.
        tenant: Authenticated tenant context from JWT.
        service: MigrationService dependency.

    Returns:
        MigrationPlanResponse for the newly created plan.

    Raises:
        HTTPException 404: If discovery not found.
        HTTPException 409: If discovery is already migrated or dismissed.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    try:
        plan = await service.start_migration(
            tool_id=tool_id,
            tenant_id=tenant_id,
            governed_tool_name=request_body.governed_tool_name,
            governed_model_id=request_body.governed_model_id,
            employee_id=request_body.employee_id,
        )
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    logger.info(
        "Migration workflow started via API",
        tenant_id=str(tenant_id),
        tool_id=str(tool_id),
        plan_id=str(plan.id),
    )
    return MigrationPlanResponse.model_validate(plan)


# ---------------------------------------------------------------------------
# Dashboard endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/shadow-ai/dashboard",
    response_model=DashboardResponse,
    summary="Usage analytics dashboard",
    description=(
        "Retrieve shadow AI usage analytics including discovery trends, "
        "risk distribution, and migration completion rates."
    ),
)
async def get_dashboard(
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    days: int = 30,
    service: DashboardService = Depends(_get_dashboard_service),
) -> DashboardResponse:
    """Retrieve the usage analytics dashboard for the current tenant.

    Args:
        tenant: Authenticated tenant context from JWT.
        days: Number of days to include in the aggregation (default 30).
        service: DashboardService dependency.

    Returns:
        DashboardResponse with usage trends and risk distribution.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)
    stats = await service.get_dashboard(tenant_id=tenant_id, days=min(days, 365))

    top_tools_raw: list[dict[str, object]] = stats.get("top_tools", [])
    trend_raw: list[dict[str, object]] = stats.get("trend", [])

    top_tools = [
        DashboardTopTool(
            tool_name=str(t["tool_name"]),
            count=int(str(t.get("count", 0))),
            risk_level=str(t.get("risk_level", "unknown")),
            active_users=int(str(t.get("active_users", 0))),
        )
        for t in top_tools_raw
    ]

    trend = [
        DashboardTrendPoint(
            date=str(p["date"]),
            count=int(str(p.get("count", 0))),
            risk_level=str(p.get("risk_level", "unknown")),
        )
        for p in trend_raw
    ]

    return DashboardResponse(
        period_days=min(days, 365),
        total_discoveries=stats.get("total_discoveries", 0),
        active_users=stats.get("active_users", 0),
        critical_count=stats.get("critical_count", 0),
        high_count=stats.get("high_count", 0),
        medium_count=stats.get("medium_count", 0),
        low_count=stats.get("low_count", 0),
        migrations_started=stats.get("migrations_started", 0),
        migrations_completed=stats.get("migrations_completed", 0),
        estimated_breach_cost_usd=stats.get("estimated_breach_cost_usd", 0.0),
        top_tools=top_tools,
        trend=trend,
        generated_at=datetime.now(tz=timezone.utc),
    )
