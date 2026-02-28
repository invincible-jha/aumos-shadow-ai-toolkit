"""FastAPI router for real-time proxy webhook events.

Receives connection events from forward proxies (Squid, Zscaler, Palo Alto NGFW)
that detect HTTPS traffic to known AI API endpoints in real time.

Returns 202 Accepted immediately; heavy processing (Kafka publishing, endpoint
matching) runs synchronously but is designed to complete within the 500 ms SLA.
DB persistence runs in a background task so the HTTP response is not blocked.

GAP-245: Real-Time Detection (<1 s Latency)
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.database import get_db_session
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.api.schemas import (
    ProxyConnectionEventRequest,
    ProxyEventAcceptedResponse,
)
from aumos_shadow_ai_toolkit.core.extension_services import ProxyEventService, verify_proxy_api_key

logger = get_logger(__name__)

router = APIRouter(prefix="/shadow-ai/webhook", tags=["proxy-webhook"])


def _get_proxy_service(request: Request) -> ProxyEventService:
    """Retrieve ProxyEventService from app state.

    Args:
        request: FastAPI request with app state.

    Returns:
        ProxyEventService instance.
    """
    return request.app.state.proxy_event_service  # type: ignore[no-any-return]


@router.post(
    "/proxy-event",
    response_model=ProxyEventAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest real-time proxy event",
    description=(
        "Receive a connection event from a forward proxy that detected HTTPS traffic "
        "to a known AI API endpoint. Processing is asynchronous — 202 is returned "
        "immediately. Source IP is used only for identity resolution and is never stored."
    ),
)
async def ingest_proxy_event(
    payload: ProxyConnectionEventRequest,
    background_tasks: BackgroundTasks,
    api_key_valid: Annotated[None, Depends(verify_proxy_api_key)],
    db: AsyncSession = Depends(get_db_session),
    service: ProxyEventService = Depends(_get_proxy_service),
) -> ProxyEventAcceptedResponse:
    """Receive a real-time proxy connection event.

    Authenticates via shared API key (machine-to-machine). Returns 202 immediately
    and processes the event in the background to meet the sub-500 ms latency target.

    Args:
        payload: Proxy connection event metadata.
        background_tasks: FastAPI background task runner.
        api_key_valid: Result of proxy API key dependency (raises 401 if invalid).
        db: Async database session.
        service: ProxyEventService dependency.

    Returns:
        ProxyEventAcceptedResponse with an assigned event_id.
    """
    event_id = uuid.uuid4()

    background_tasks.add_task(
        service.process_event,
        tenant_id=payload.tenant_id,
        destination_host=payload.destination_host,
        destination_port=payload.destination_port,
        source_ip=payload.source_ip,
        protocol=payload.protocol,
        bytes_sent=payload.bytes_sent,
        event_timestamp=payload.event_timestamp,
        proxy_source=payload.proxy_source,
        db=db,
    )

    logger.info(
        "Proxy event accepted",
        event_id=str(event_id),
        tenant_id=str(payload.tenant_id),
        destination_host=payload.destination_host,
        proxy_source=payload.proxy_source,
    )

    return ProxyEventAcceptedResponse(event_id=event_id)
