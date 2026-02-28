"""Business logic services for browser extension telemetry, proxy events, MCP discovery,
endpoint registry, and user nudge coaching.

GAP-244: ExtensionTelemetryService
GAP-245: ProxyEventService
GAP-246: MCPDiscoveryService
GAP-247: EndpointRegistryService
GAP-248: NudgeService
GAP-249: OktaIdentityResolverAdapter (in adapters/identity_resolver.py)
"""

from __future__ import annotations

import hmac
import statistics
import uuid
from datetime import datetime, timezone
from typing import ClassVar

from fastapi import Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from aumos_common.errors import NotFoundError, ErrorCode
from aumos_common.events import EventPublisher, Topics
from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.api.schemas import (
    ExtensionTelemetryResponse,
)
from aumos_shadow_ai_toolkit.core.models import (
    SatExtensionTelemetry,
    SatMcpDiscovery,
    SatNudgeEvent,
    SatProxyEvent,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# GAP-248: Nudge configuration value object
# ---------------------------------------------------------------------------


class NudgeConfiguration:
    """Per-tenant nudge system configuration.

    Args:
        nudging_enabled: Whether nudges are active for this tenant.
        company_name: Company display name for nudge messages.
        primary_data_region: Primary data jurisdiction (e.g. EU, US).
    """

    def __init__(
        self,
        nudging_enabled: bool = True,
        company_name: str = "your organisation",
        primary_data_region: str = "your region",
    ) -> None:
        self.nudging_enabled = nudging_enabled
        self.company_name = company_name
        self.primary_data_region = primary_data_region


# ---------------------------------------------------------------------------
# GAP-246: Network flow record value object
# ---------------------------------------------------------------------------


class NetworkFlowRecord:
    """A network flow metadata record from a proxy or CASB integration.

    Metadata only — no content inspection.
    """

    def __init__(
        self,
        destination_host: str,
        connection_duration_seconds: float,
        bytes_per_second: float,
        request_count_per_minute: int,
        http_method: str,
        timestamp: datetime,
    ) -> None:
        self.destination_host = destination_host
        self.connection_duration_seconds = connection_duration_seconds
        self.bytes_per_second = bytes_per_second
        self.request_count_per_minute = request_count_per_minute
        self.http_method = http_method
        self.timestamp = timestamp


class MCPDiscoveryResult:
    """A single MCP or agent discovery result."""

    def __init__(
        self,
        tenant_id: uuid.UUID,
        connection_type: str,
        destination_host: str,
        estimated_server_type: str | None,
        first_seen: datetime,
    ) -> None:
        self.tenant_id = tenant_id
        self.connection_type = connection_type
        self.destination_host = destination_host
        self.estimated_server_type = estimated_server_type
        self.first_seen = first_seen


# ---------------------------------------------------------------------------
# GAP-248: NudgeService
# ---------------------------------------------------------------------------


class NudgeService:
    """Generates contextual coaching nudges for shadow AI tool users.

    Nudges are non-blocking — users can dismiss and proceed. They create
    behavioral friction without productivity disruption.

    Args:
        settings: Shadow AI settings containing nudge configuration.
    """

    NUDGE_TEMPLATES: ClassVar[dict[str, str]] = {
        "critical": (
            "This tool does not meet {company} data security standards. "
            "Data sent here may leave {region} jurisdiction. "
            "Try {governed_alternative} instead."
        ),
        "high": (
            "Using personal AI accounts risks {specific_concern}. "
            "Your company provides {governed_alternative} for this task."
        ),
        "medium": "Consider using {governed_alternative} for better data protection.",
    }

    _SPECIFIC_CONCERNS: ClassVar[dict[str, str]] = {
        "chat.openai.com": "IP and confidential data exposure",
        "claude.ai": "data leaving your organisation's control",
        "perplexity.ai": "uncontrolled data processing",
    }

    def __init__(self, settings: object) -> None:
        """Initialise with Shadow AI service settings.

        Args:
            settings: Settings instance (typed as object for decoupling).
        """
        self._settings = settings

    async def generate_nudge(
        self,
        tool_domain: str,
        tool_name: str,
        risk_level: str,
        governed_alternative: str | None,
        tenant_config: NudgeConfiguration,
    ) -> str | None:
        """Generate a contextual coaching nudge for the given tool and risk level.

        Args:
            tool_domain: Domain of the detected shadow AI tool.
            tool_name: Human-readable tool name.
            risk_level: Risk classification: critical | high | medium | low.
            governed_alternative: Governed alternative tool name if available.
            tenant_config: Per-tenant nudge system configuration.

        Returns:
            Nudge message string, or None if nudging is disabled or risk is low.
        """
        if not tenant_config.nudging_enabled or risk_level == "low":
            return None

        template = self.NUDGE_TEMPLATES.get(risk_level)
        if not template:
            return None

        alternative = governed_alternative or "an approved AumOS service"
        specific_concern = self._SPECIFIC_CONCERNS.get(
            tool_domain, "uncontrolled data processing outside your organisation"
        )

        return template.format(
            company=tenant_config.company_name,
            region=tenant_config.primary_data_region,
            governed_alternative=alternative,
            specific_concern=specific_concern,
        )

    async def record_nudge(
        self,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID,
        tool_domain: str,
        risk_level: str,
        nudge_message: str,
        governed_alternative: str | None,
        telemetry_id: uuid.UUID | None,
        db: AsyncSession,
    ) -> SatNudgeEvent:
        """Persist a nudge delivery record.

        Args:
            tenant_id: Owning tenant UUID.
            user_id: User who received the nudge.
            tool_domain: Shadow AI tool domain.
            risk_level: Risk level that triggered the nudge.
            nudge_message: The message delivered.
            governed_alternative: Governed alternative suggested.
            telemetry_id: Linked extension telemetry record UUID.
            db: Async database session.

        Returns:
            Persisted SatNudgeEvent record.
        """
        nudge_event = SatNudgeEvent(
            tenant_id=tenant_id,
            user_id=user_id,
            tool_domain=tool_domain,
            risk_level=risk_level,
            nudge_message=nudge_message,
            governed_alternative=governed_alternative,
            dismissed=False,
            clicked_alternative=False,
            telemetry_id=telemetry_id,
        )
        db.add(nudge_event)
        await db.flush()

        logger.info(
            "Nudge event recorded",
            tenant_id=str(tenant_id),
            user_id=str(user_id),
            tool_domain=tool_domain,
            risk_level=risk_level,
        )

        return nudge_event


# ---------------------------------------------------------------------------
# GAP-244: ExtensionTelemetryService
# ---------------------------------------------------------------------------


class ExtensionTelemetryService:
    """Processes browser extension telemetry events.

    Ingests navigation metadata from the AumOS Shadow AI Detector extension,
    creates or updates discovery records, assesses risk, and publishes Kafka
    events. Returns immediate risk feedback and optional nudge messages.

    Args:
        event_publisher: Kafka event publisher.
        nudge_service: NudgeService for generating coaching messages.
        settings: Shadow AI settings with extension configuration.
    """

    def __init__(
        self,
        event_publisher: EventPublisher,
        nudge_service: NudgeService,
        settings: object,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            event_publisher: Kafka event publisher.
            nudge_service: NudgeService for nudge generation.
            settings: Shadow AI settings.
        """
        self._publisher = event_publisher
        self._nudge_service = nudge_service
        self._settings = settings
        # In-memory deduplication: (tenant_id, user_id, tool_domain) → last_event_ts
        self._dedup_cache: dict[tuple[str, str, str], datetime] = {}

    async def ingest_telemetry(
        self,
        tenant_id: uuid.UUID,
        tool_domain: str,
        tool_name: str,
        session_duration_seconds: int | None,
        browser_family: str,
        extension_version: str,
        timestamp_utc: datetime,
        db: AsyncSession,
    ) -> ExtensionTelemetryResponse:
        """Ingest a browser navigation event, assess risk, and publish Kafka event.

        Deduplicates within a 24-hour window per (tenant, tool_domain) pair
        to prevent event storms. Returns risk level and optional nudge message.

        Args:
            tenant_id: Owning tenant UUID.
            tool_domain: Domain of the AI tool navigated to.
            tool_name: Human-readable tool name.
            session_duration_seconds: Estimated session duration from extension.
            browser_family: Browser family: chrome | edge | firefox.
            extension_version: Extension version string.
            timestamp_utc: UTC timestamp of the navigation event.
            db: Async database session.

        Returns:
            ExtensionTelemetryResponse with risk classification and optional nudge.
        """
        # Compute risk level from base settings (simplified — uses registry if available)
        risk_level = self._classify_domain_risk(tool_domain)

        # Persist telemetry record
        telemetry = SatExtensionTelemetry(
            tenant_id=tenant_id,
            user_id=uuid.uuid4(),  # Resolved from JWT in production; placeholder here
            tool_domain=tool_domain,
            tool_name=tool_name,
            session_duration_seconds=session_duration_seconds,
            browser_family=browser_family,
            extension_version=extension_version,
            risk_level=risk_level,
            nudge_delivered=False,
            event_timestamp=timestamp_utc,
        )
        db.add(telemetry)
        await db.flush()

        # Publish Kafka event for new unique detections (24-hour deduplication window)
        dedup_key = (str(tenant_id), tool_domain)
        should_publish = self._should_publish_event(dedup_key, timestamp_utc)

        if should_publish:
            await self._publisher.publish(
                Topics.SHADOW_AI_EVENTS,
                {
                    "event_type": "shadow_ai.extension_detected",
                    "tenant_id": str(tenant_id),
                    "telemetry_id": str(telemetry.id),
                    "tool_domain": tool_domain,
                    "tool_name": tool_name,
                    "risk_level": risk_level,
                    "timestamp_utc": timestamp_utc.isoformat(),
                },
            )
            self._dedup_cache[dedup_key] = timestamp_utc

        # Generate nudge message
        tenant_config = NudgeConfiguration()  # Default config; override from settings in production
        nudge_message = await self._nudge_service.generate_nudge(
            tool_domain=tool_domain,
            tool_name=tool_name,
            risk_level=risk_level,
            governed_alternative=None,
            tenant_config=tenant_config,
        )

        if nudge_message:
            telemetry.nudge_delivered = True

        logger.info(
            "Extension telemetry processed",
            tenant_id=str(tenant_id),
            telemetry_id=str(telemetry.id),
            tool_domain=tool_domain,
            risk_level=risk_level,
            nudge_delivered=bool(nudge_message),
        )

        return ExtensionTelemetryResponse(
            telemetry_id=telemetry.id,
            risk_level=risk_level,  # type: ignore[arg-type]
            governed_alternative=None,
            nudge_message=nudge_message,
        )

    def _classify_domain_risk(self, tool_domain: str) -> str:
        """Classify domain risk using a simple heuristic.

        In production this defers to the EndpointRegistryService cache.

        Args:
            tool_domain: Domain to classify.

        Returns:
            Risk level string: critical | high | medium | low.
        """
        high_risk_domains = {
            "chat.openai.com", "claude.ai", "perplexity.ai",
            "gemini.google.com", "copilot.microsoft.com",
        }
        if tool_domain in high_risk_domains:
            return "high"
        if "openai" in tool_domain or "anthropic" in tool_domain:
            return "critical"
        return "medium"

    def _should_publish_event(
        self,
        dedup_key: tuple[str, str],
        current_timestamp: datetime,
    ) -> bool:
        """Check 24-hour deduplication window to prevent event storms.

        Args:
            dedup_key: (tenant_id, tool_domain) tuple.
            current_timestamp: Current event timestamp.

        Returns:
            True if event should be published (not seen in last 24 hours).
        """
        last_seen = self._dedup_cache.get(dedup_key)
        if last_seen is None:
            return True
        delta = current_timestamp - last_seen
        return delta.total_seconds() > 86400  # 24 hours


# ---------------------------------------------------------------------------
# GAP-245: ProxyEventService
# ---------------------------------------------------------------------------


class ProxyEventService:
    """Processes real-time proxy connection events for shadow AI detection.

    Designed for sub-500ms processing of proxy webhook events. Returns HTTP
    202 immediately; processing occurs in a FastAPI BackgroundTask.

    Args:
        event_publisher: Kafka event publisher for real-time alerts.
        settings: Shadow AI settings with risk thresholds.
    """

    def __init__(
        self,
        event_publisher: EventPublisher,
        settings: object,
    ) -> None:
        """Initialise with injected dependencies.

        Args:
            event_publisher: Kafka event publisher.
            settings: Shadow AI settings.
        """
        self._publisher = event_publisher
        self._settings = settings
        self._endpoint_cache: dict[str, dict] = {}

    async def process_event(
        self,
        tenant_id: uuid.UUID,
        destination_host: str,
        destination_port: int,
        source_ip: str,
        protocol: str,
        bytes_sent: int | None,
        event_timestamp: datetime,
        proxy_source: str,
        db: AsyncSession,
    ) -> SatProxyEvent:
        """Process a real-time proxy connection event.

        Matches destination host against the endpoint registry, creates
        a proxy event record, and publishes a Kafka alert if risk threshold
        is met.

        Args:
            tenant_id: Tenant scope.
            destination_host: Destination hostname from proxy.
            destination_port: Destination port.
            source_ip: Internal source IP for identity resolution.
            protocol: CONNECT | HTTPS | HTTP.
            bytes_sent: Bytes sent by client.
            event_timestamp: UTC timestamp of proxy event.
            proxy_source: Proxy identifier string.
            db: Async database session.

        Returns:
            Persisted SatProxyEvent record.
        """
        matched_tool, risk_level = self._match_endpoint(destination_host)
        action_taken = "logged"

        if risk_level in ("critical", "high"):
            action_taken = "alerted"
            await self._publisher.publish(
                Topics.SHADOW_AI_EVENTS,
                {
                    "event_type": "shadow_ai.realtime_detected",
                    "tenant_id": str(tenant_id),
                    "destination_host": destination_host,
                    "matched_tool": matched_tool,
                    "risk_level": risk_level,
                    "proxy_source": proxy_source,
                    "event_timestamp": event_timestamp.isoformat(),
                },
            )

        proxy_event = SatProxyEvent(
            tenant_id=tenant_id,
            destination_host=destination_host,
            destination_port=destination_port,
            source_ip=source_ip,
            protocol=protocol,
            bytes_sent=bytes_sent,
            event_timestamp=event_timestamp,
            proxy_source=proxy_source,
            matched_tool=matched_tool,
            risk_level=risk_level,
            action_taken=action_taken,
        )
        db.add(proxy_event)
        await db.flush()

        logger.info(
            "Proxy event processed",
            tenant_id=str(tenant_id),
            destination_host=destination_host,
            matched_tool=matched_tool,
            action_taken=action_taken,
        )

        return proxy_event

    def _match_endpoint(self, destination_host: str) -> tuple[str | None, str | None]:
        """Match destination host against known AI endpoint registry cache.

        Args:
            destination_host: Hostname to look up.

        Returns:
            Tuple of (tool_name, risk_level) or (None, None) if no match.
        """
        known: dict[str, tuple[str, str]] = {
            "api.openai.com": ("OpenAI API", "critical"),
            "chat.openai.com": ("ChatGPT Personal", "high"),
            "api.anthropic.com": ("Anthropic API", "critical"),
            "claude.ai": ("Claude Personal", "high"),
            "api.perplexity.ai": ("Perplexity AI", "high"),
            "generativelanguage.googleapis.com": ("Google Gemini API", "high"),
        }
        match = known.get(destination_host)
        if match:
            return match
        return None, None


async def verify_proxy_api_key(
    x_proxy_api_key: str = Header(..., alias="X-Proxy-API-Key"),
    settings: object = None,  # injected via Depends in router
) -> None:
    """Verify that the incoming proxy webhook API key is valid.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        x_proxy_api_key: API key from X-Proxy-API-Key header.
        settings: Shadow AI settings containing the expected key.

    Raises:
        HTTPException 401: If the API key is invalid.
    """
    expected_key = getattr(settings, "proxy_webhook_api_key", "") if settings else ""
    if not hmac.compare_digest(x_proxy_api_key, str(expected_key)):
        raise HTTPException(status_code=401, detail="Invalid proxy API key")


# ---------------------------------------------------------------------------
# GAP-246: MCPDiscoveryAdapter
# ---------------------------------------------------------------------------


class MCPDiscoveryAdapter:
    """Detects Model Context Protocol server connections and autonomous agent activity.

    MCP uses Server-Sent Events (SSE) for the server-to-client stream and
    HTTP POST for client-to-server messages. Distinctive signatures:
    - SSE connection to known MCP-capable hosts (long-lived, low byte count)
    - High-frequency structured POST to LLM API endpoints (agent burst pattern)

    Args:
        settings: Shadow AI settings with MCP endpoint registry.
    """

    def __init__(self, settings: object) -> None:
        """Initialise with injected settings.

        Args:
            settings: Shadow AI settings.
        """
        self._settings = settings

    async def detect_mcp_connections(
        self,
        tenant_id: uuid.UUID,
        network_flow_sample: list[NetworkFlowRecord],
    ) -> list[MCPDiscoveryResult]:
        """Analyse network flow metadata for MCP protocol signatures.

        Args:
            tenant_id: Tenant scope.
            network_flow_sample: Network metadata records (no content).

        Returns:
            List of detected MCP server connections and agent bursts.
        """
        discoveries: list[MCPDiscoveryResult] = []

        for flow in network_flow_sample:
            if self._is_mcp_sse_connection(flow):
                discoveries.append(
                    MCPDiscoveryResult(
                        tenant_id=tenant_id,
                        connection_type="mcp_sse",
                        destination_host=flow.destination_host,
                        estimated_server_type=self._classify_mcp_server(flow.destination_host),
                        first_seen=flow.timestamp,
                    )
                )
            elif self._is_agent_api_burst(flow):
                discoveries.append(
                    MCPDiscoveryResult(
                        tenant_id=tenant_id,
                        connection_type="agent_api_burst",
                        destination_host=flow.destination_host,
                        estimated_server_type="autonomous_agent",
                        first_seen=flow.timestamp,
                    )
                )

        return discoveries

    def _is_mcp_sse_connection(self, flow: NetworkFlowRecord) -> bool:
        """SSE connections: long-lived, low byte count (heartbeat pattern).

        Args:
            flow: Network flow record to evaluate.

        Returns:
            True if the flow matches MCP SSE connection characteristics.
        """
        mcp_known_hosts: list[str] = getattr(
            self._settings, "mcp_known_hosts", ["mcp.anthropic.com", "api.openai.com"]
        )
        return (
            flow.destination_host in mcp_known_hosts
            and flow.connection_duration_seconds > 30
            and flow.bytes_per_second < 100
        )

    def _is_agent_api_burst(self, flow: NetworkFlowRecord) -> bool:
        """Agent API bursts: high frequency POSTs to LLM endpoints.

        Args:
            flow: Network flow record to evaluate.

        Returns:
            True if the flow matches agent API burst characteristics.
        """
        agent_burst_threshold: int = getattr(self._settings, "agent_burst_threshold", 30)
        known_ai_endpoints: list[str] = getattr(self._settings, "known_ai_endpoints", [])
        return (
            flow.destination_host in known_ai_endpoints
            and flow.request_count_per_minute > agent_burst_threshold
            and flow.http_method == "POST"
        )

    def _classify_mcp_server(self, destination_host: str) -> str:
        """Classify an MCP server type from its hostname.

        Args:
            destination_host: MCP server hostname.

        Returns:
            Estimated server type string.
        """
        if "anthropic" in destination_host:
            return "claude_mcp_server"
        if "openai" in destination_host:
            return "openai_mcp_server"
        return "unknown_mcp_server"

    async def persist_discoveries(
        self,
        discoveries: list[MCPDiscoveryResult],
        tenant_id: uuid.UUID,
        event_publisher: EventPublisher,
        db: AsyncSession,
    ) -> list[SatMcpDiscovery]:
        """Persist MCP discovery records and publish Kafka events.

        Args:
            discoveries: List of MCPDiscoveryResult from detect_mcp_connections.
            tenant_id: Owning tenant UUID.
            event_publisher: Kafka event publisher.
            db: Async database session.

        Returns:
            List of persisted SatMcpDiscovery records.
        """
        records: list[SatMcpDiscovery] = []
        now = datetime.now(tz=timezone.utc)

        for discovery in discoveries:
            record = SatMcpDiscovery(
                tenant_id=tenant_id,
                connection_type=discovery.connection_type,
                destination_host=discovery.destination_host,
                estimated_server_type=discovery.estimated_server_type,
                first_seen=discovery.first_seen,
                last_seen=now,
                connection_metadata={},
            )
            db.add(record)
            await db.flush()

            await event_publisher.publish(
                Topics.SHADOW_AI_EVENTS,
                {
                    "event_type": "shadow_ai.mcp_detected",
                    "tenant_id": str(tenant_id),
                    "discovery_id": str(record.id),
                    "connection_type": discovery.connection_type,
                    "destination_host": discovery.destination_host,
                    "estimated_server_type": discovery.estimated_server_type,
                },
            )

            records.append(record)

        return records


# ---------------------------------------------------------------------------
# GAP-247: EndpointRegistryService
# ---------------------------------------------------------------------------


class EndpointRegistryService:
    """Manages the curated AI endpoint registry.

    Provides CRUD operations for registry entries and loads the full
    registry into an in-memory cache at startup for O(1) lookup.

    Args:
        settings: Shadow AI settings.
    """

    def __init__(self, settings: object) -> None:
        """Initialise with Shadow AI settings.

        Args:
            settings: Shadow AI settings.
        """
        self._settings = settings
        self._cache: dict[str, dict] = {}

    async def load_registry_to_cache(self, db: AsyncSession) -> dict[str, dict]:
        """Load full active registry into in-memory dict for O(1) scan lookup.

        Called at service startup via lifespan hook.

        Args:
            db: Async database session.

        Returns:
            Dict mapping domain → registry entry metadata.
        """
        from sqlalchemy import select

        from aumos_shadow_ai_toolkit.core.models import SatAiEndpointRegistry

        result = await db.execute(
            select(SatAiEndpointRegistry).where(SatAiEndpointRegistry.is_active.is_(True))
        )
        entries = result.scalars().all()

        self._cache = {
            entry.domain: {
                "tool_name": entry.tool_name,
                "vendor": entry.vendor,
                "category": entry.category,
                "base_risk_score": entry.base_risk_score,
                "governed_alternative_hint": entry.governed_alternative_hint,
                "gdpr_compliant": entry.gdpr_compliant,
                "hipaa_compliant": entry.hipaa_compliant,
            }
            for entry in entries
        }

        logger.info("Endpoint registry cache loaded", entry_count=len(self._cache))
        return self._cache

    def lookup(self, domain: str) -> dict | None:
        """Look up a domain in the in-memory registry cache.

        Args:
            domain: Domain to look up.

        Returns:
            Registry entry dict or None if not found.
        """
        return self._cache.get(domain)

    def get_cache_version(self) -> int:
        """Return the number of active entries as a version proxy.

        Returns:
            Count of entries in the in-memory cache.
        """
        return len(self._cache)
