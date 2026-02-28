"""FastAPI router for browser extension telemetry ingestion.

Receives navigation metadata from the AumOS Shadow AI Detector browser extension.
Content is NEVER read — only domain, timestamp, and session duration metadata.

GAP-244: Browser Extension / Endpoint Agent
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.auth import TenantContext, get_current_tenant
from aumos_common.database import get_db_session
from aumos_common.errors import NotFoundError
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.api.schemas import (
    ExtensionTelemetryRequest,
    ExtensionTelemetryResponse,
)
from aumos_shadow_ai_toolkit.core.extension_services import ExtensionTelemetryService

logger = get_logger(__name__)

router = APIRouter(prefix="/shadow-ai/extension", tags=["extension"])


def _get_extension_service(request: Request) -> ExtensionTelemetryService:
    """Retrieve ExtensionTelemetryService from app state.

    Args:
        request: FastAPI request with app state.

    Returns:
        ExtensionTelemetryService instance.
    """
    return request.app.state.extension_telemetry_service  # type: ignore[no-any-return]


@router.post(
    "/telemetry",
    response_model=ExtensionTelemetryResponse,
    summary="Ingest browser extension telemetry",
    description=(
        "Receive AI tool navigation events from the AumOS Shadow AI Detector browser extension. "
        "Only navigation metadata is accepted — page content, DOM, or form data is NEVER sent."
    ),
)
async def ingest_extension_telemetry(
    payload: ExtensionTelemetryRequest,
    background_tasks: BackgroundTasks,
    tenant: Annotated[TenantContext, Depends(get_current_tenant)],
    session: AsyncSession = Depends(get_db_session),
    service: ExtensionTelemetryService = Depends(_get_extension_service),
) -> ExtensionTelemetryResponse:
    """Receive a browser navigation event from the AumOS extension.

    Processes telemetry asynchronously to minimise extension latency.
    Returns risk level and optional nudge message immediately.

    Args:
        payload: Navigation metadata from the extension.
        background_tasks: FastAPI background task runner.
        tenant: Authenticated tenant context.
        session: Async database session.
        service: ExtensionTelemetryService dependency.

    Returns:
        ExtensionTelemetryResponse with telemetry_id, risk_level, and optional nudge.
    """
    tenant_id = uuid.UUID(tenant.tenant_id)

    result = await service.ingest_telemetry(
        tenant_id=tenant_id,
        tool_domain=payload.tool_domain,
        tool_name=payload.tool_name,
        session_duration_seconds=payload.session_duration_seconds,
        browser_family=payload.browser_family,
        extension_version=payload.extension_version,
        timestamp_utc=payload.timestamp_utc,
        db=session,
    )

    logger.info(
        "Extension telemetry ingested",
        tenant_id=str(tenant_id),
        telemetry_id=str(result.telemetry_id),
        tool_domain=payload.tool_domain,
        risk_level=result.risk_level,
    )

    return result
