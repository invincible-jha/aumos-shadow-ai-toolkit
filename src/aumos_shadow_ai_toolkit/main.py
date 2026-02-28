"""AumOS Shadow AI Toolkit service entry point."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from aumos_common.app import create_app
from aumos_common.database import init_database
from aumos_common.health import HealthCheck
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.adapters.kafka import ShadowAIEventPublisher
from aumos_shadow_ai_toolkit.api.extension_router import router as extension_router
from aumos_shadow_ai_toolkit.api.proxy_router import router as proxy_router
from aumos_shadow_ai_toolkit.api.router import router
from aumos_shadow_ai_toolkit.api.routes.shadow_ai import router as shadow_ai_detection_router
from aumos_shadow_ai_toolkit.core.extension_services import (
    EndpointRegistryService,
    ExtensionTelemetryService,
    MCPDiscoveryAdapter,
    NudgeService,
    ProxyEventService,
)
from aumos_shadow_ai_toolkit.settings import Settings

logger = get_logger(__name__)
settings = Settings()

_kafka_publisher: ShadowAIEventPublisher | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown lifecycle.

    Initialises the database connection pool, Kafka event publisher,
    and exposes services on app.state for dependency injection.

    Args:
        app: The FastAPI application instance.

    Yields:
        None
    """
    global _kafka_publisher  # noqa: PLW0603

    logger.info("Starting AumOS Shadow AI Toolkit", version="0.1.0")

    # Database connection pool
    init_database(settings.database)
    logger.info("Database connection pool ready")

    # Kafka event publisher
    _kafka_publisher = ShadowAIEventPublisher(settings.kafka)
    await _kafka_publisher.start()
    app.state.kafka_publisher = _kafka_publisher
    logger.info("Kafka event publisher ready")

    # Expose settings on app state for dependency injection
    app.state.settings = settings

    # GAP-248: Nudge service
    nudge_service = NudgeService(settings=settings)
    app.state.nudge_service = nudge_service

    # GAP-244: Extension telemetry service
    extension_telemetry_service = ExtensionTelemetryService(
        event_publisher=_kafka_publisher,
        nudge_service=nudge_service,
        settings=settings,
    )
    app.state.extension_telemetry_service = extension_telemetry_service

    # GAP-245: Proxy event service
    proxy_event_service = ProxyEventService(
        event_publisher=_kafka_publisher,
        settings=settings,
    )
    app.state.proxy_event_service = proxy_event_service

    # GAP-246: MCP discovery adapter
    mcp_discovery_adapter = MCPDiscoveryAdapter(settings=settings)
    app.state.mcp_discovery_adapter = mcp_discovery_adapter

    # GAP-247: Endpoint registry service
    endpoint_registry_service = EndpointRegistryService()
    app.state.endpoint_registry_service = endpoint_registry_service

    logger.info("Shadow AI Toolkit service startup complete")
    yield

    # Shutdown
    if _kafka_publisher:
        await _kafka_publisher.stop()

    logger.info("Shadow AI Toolkit service shutdown complete")


app: FastAPI = create_app(
    service_name="aumos-shadow-ai-toolkit",
    version="0.1.0",
    settings=settings,
    lifespan=lifespan,
    health_checks=[
        HealthCheck(name="postgres", check_fn=lambda: None),
        HealthCheck(name="kafka", check_fn=lambda: None),
    ],
)

app.include_router(router, prefix="/api/v1")
app.include_router(shadow_ai_detection_router, prefix="/api/v1")
app.include_router(extension_router, prefix="/api/v1")
app.include_router(proxy_router, prefix="/api/v1")
