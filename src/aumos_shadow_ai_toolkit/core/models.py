"""SQLAlchemy ORM models for the AumOS Shadow AI Toolkit service.

All tables use the `sat_` prefix. Tenant-scoped tables extend AumOSModel
which supplies id (UUID), tenant_id, created_at, and updated_at columns.

Domain model:
  ShadowAIDiscovery    — detected unauthorized AI tool usage per tenant
  MigrationPlan        — migration workflow from shadow to governed tool
  ScanResult           — history of network scan executions
  UsageMetric          — aggregated shadow AI usage analytics over time
  SatExtensionTelemetry — browser extension navigation events (GAP-244)
  SatProxyEvent         — real-time proxy webhook events (GAP-245)
  SatMcpDiscovery       — MCP server and agent API burst detections (GAP-246)
  SatAiEndpointRegistry — curated AI tool endpoint database (GAP-247)
  SatNudgeEvent         — user coaching nudge delivery records (GAP-248)
"""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from aumos_common.database import AumOSModel, Base


class ShadowAIDiscovery(AumOSModel):
    """A detected instance of unauthorized AI tool usage.

    Records the network metadata of an employee using an unsanctioned AI
    service. Content is never stored — only metadata (destination, frequency,
    estimated data volume). Risk score is computed by RiskAssessorService
    immediately after detection.

    Status lifecycle:
        detected → assessed → notified → migrating → migrated
        detected → assessed → dismissed

    Table: sat_discoveries
    """

    __tablename__ = "sat_discoveries"

    tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Human-readable name of the detected AI tool (e.g., ChatGPT, Claude.ai)",
    )
    api_endpoint: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        comment="Detected API domain/endpoint (e.g., api.openai.com)",
    )
    detection_method: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="dns_pattern | tls_sni | http_connect | api_key_pattern",
    )
    detected_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="UUID of the employee whose traffic was detected (from IAM, no FK)",
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Composite risk score (0.0–1.0) combining data sensitivity and compliance exposure",
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        index=True,
        comment="critical | high | medium | low | unknown",
    )
    data_sensitivity: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="unknown",
        comment="Estimated data sensitivity: pii | financial | ip | internal | public | unknown",
    )
    compliance_exposure: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of compliance frameworks at risk: [GDPR, HIPAA, SOC2, PCI_DSS]",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="detected",
        index=True,
        comment="detected | assessed | notified | migrating | migrated | dismissed",
    )
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the first detection event for this tool+user combination",
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the most recent detection event",
    )
    request_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total number of detected API calls (metadata count only)",
    )
    estimated_data_volume_kb: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Estimated total data transferred in kilobytes (metadata estimate only)",
    )
    scan_result_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sat_scan_results.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="Scan result that first detected this discovery",
    )
    risk_details: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Detailed risk assessment breakdown from RiskAssessorService",
    )
    dismissed_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reason for dismissal if status=dismissed",
    )

    migration_plans: Mapped[list["MigrationPlan"]] = relationship(
        "MigrationPlan",
        back_populates="discovery",
        cascade="all, delete-orphan",
    )
    scan_result: Mapped["ScanResult | None"] = relationship(
        "ScanResult",
        back_populates="discoveries",
    )


class MigrationPlan(AumOSModel):
    """Migration workflow from a shadow AI tool to a governed alternative.

    Created by MigrationService when an employee is ready to transition from
    an unauthorized tool to a sanctioned enterprise alternative. Plans expire
    after `migration_expiry_days` if not acted on.

    Status lifecycle:
        pending → in_progress → completed
        pending → in_progress → failed
        pending → expired

    Table: sat_migration_plans
    """

    __tablename__ = "sat_migration_plans"

    discovery_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sat_discoveries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="Parent shadow AI discovery UUID",
    )
    employee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="UUID of the employee being migrated (from IAM, no FK)",
    )
    shadow_tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Name of the unauthorized tool being replaced",
    )
    governed_tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Name of the sanctioned governed alternative being offered",
    )
    governed_model_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID reference to the model in aumos-model-registry (no FK constraint)",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
        comment="pending | in_progress | completed | failed | expired",
    )
    approval_workflow_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the aumos-approval-workflow instance (no FK, cross-service)",
    )
    migration_steps: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="Ordered list of migration steps with completion status",
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when this migration plan expires if not completed",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when the migration was successfully completed",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text notes from the migration coordinator",
    )

    discovery: Mapped["ShadowAIDiscovery"] = relationship(
        "ShadowAIDiscovery",
        back_populates="migration_plans",
    )


class ScanResult(AumOSModel):
    """History record for a network scan execution.

    One ScanResult per triggered scan. Captures the scan parameters,
    duration, and summary statistics. Individual discoveries reference
    the scan that first detected them.

    Table: sat_scan_results
    """

    __tablename__ = "sat_scan_results"

    scan_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="scheduled",
        comment="scheduled | manual | triggered",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="running",
        index=True,
        comment="running | completed | failed | cancelled",
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when the scan began",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when the scan finished",
    )
    duration_seconds: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Total scan duration in seconds",
    )
    new_discoveries_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of new shadow AI tools discovered in this scan",
    )
    total_endpoints_checked: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total number of AI API endpoints checked in this scan",
    )
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Error detail if status=failed",
    )
    scan_parameters: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Parameters used for this scan (endpoints, methods, filters)",
    )

    discoveries: Mapped[list["ShadowAIDiscovery"]] = relationship(
        "ShadowAIDiscovery",
        back_populates="scan_result",
    )


class UsageMetric(AumOSModel):
    """Aggregated shadow AI usage analytics for a tenant over a time period.

    Computed by the DiscoveryService on a rolling basis from raw discoveries.
    Used to power the analytics dashboard endpoint.

    Table: sat_usage_metrics
    """

    __tablename__ = "sat_usage_metrics"

    period_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="Start of the aggregation period (UTC)",
    )
    period_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="End of the aggregation period (UTC)",
    )
    period_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="daily",
        comment="daily | weekly | monthly",
    )
    total_discoveries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total shadow AI discoveries in this period",
    )
    active_users: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of distinct employees detected using shadow AI tools",
    )
    critical_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Discoveries rated critical in this period",
    )
    high_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Discoveries rated high in this period",
    )
    medium_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Discoveries rated medium in this period",
    )
    low_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Discoveries rated low in this period",
    )
    migrations_started: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Migration plans initiated in this period",
    )
    migrations_completed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Migration plans successfully completed in this period",
    )
    top_tools: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="Top shadow AI tools by frequency: [{tool_name, count, risk_level}]",
    )
    estimated_breach_cost_usd: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
        comment="Estimated breach cost exposure in USD based on active critical/high discoveries",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="False for superseded aggregations (e.g., when a monthly replaces weeklies)",
    )


# ---------------------------------------------------------------------------
# GAP-244: Browser Extension Telemetry
# ---------------------------------------------------------------------------


class SatExtensionTelemetry(AumOSModel):
    """Stores browser extension telemetry events for shadow AI detection.

    Records navigation events forwarded by the AumOS Shadow AI Detector extension.
    Metadata only — no page content, form values, or clipboard data ever stored.

    Table: sat_extension_telemetry
    """

    __tablename__ = "sat_extension_telemetry"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="User UUID derived from the JWT in the extension API call",
    )
    tool_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Domain of the AI tool navigated to (e.g. chat.openai.com)",
    )
    tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable tool name resolved from endpoint registry",
    )
    session_duration_seconds: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Estimated session duration from tab visibility API (seconds)",
    )
    browser_family: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="chrome | edge | firefox",
    )
    extension_version: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        comment="Extension semantic version string",
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        comment="critical | high | medium | low — computed at ingest time",
    )
    nudge_delivered: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if a coaching nudge was included in the API response",
    )
    discovery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
        comment="UUID of the sat_discoveries record created or updated by this event",
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp of the browser navigation event",
    )


# ---------------------------------------------------------------------------
# GAP-245: Real-Time Proxy Events
# ---------------------------------------------------------------------------


class SatProxyEvent(AumOSModel):
    """Raw proxy connection events received from forward proxies.

    Stores events from Squid, Zscaler, Palo Alto NGFW, and mitmproxy for
    real-time shadow AI detection. IP addresses are stored for identity
    resolution only — not for content inspection.

    Table: sat_proxy_events
    """

    __tablename__ = "sat_proxy_events"

    destination_host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Destination hostname observed by the proxy",
    )
    destination_port: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=443,
        comment="Destination TCP port",
    )
    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        comment="Internal source IP (retained for identity resolution only)",
    )
    protocol: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="CONNECT | HTTPS | HTTP",
    )
    bytes_sent: Mapped[int | None] = mapped_column(
        BigInteger,
        nullable=True,
        comment="Bytes sent by client (metadata only)",
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        comment="UTC timestamp of the proxy event",
    )
    proxy_source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="Proxy that sent the event: squid | zscaler | palo_alto | mitmproxy",
    )
    matched_tool: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="AI tool name matched from endpoint registry; None if no match",
    )
    risk_level: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
        comment="Risk classification after endpoint registry match",
    )
    action_taken: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="logged",
        comment="logged | alerted | blocked",
    )
    discovery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the sat_discoveries record affected by this event",
    )


# ---------------------------------------------------------------------------
# GAP-246: MCP / Agentic AI Discoveries
# ---------------------------------------------------------------------------


class SatMcpDiscovery(AumOSModel):
    """Records of detected MCP server connections and autonomous agent activity.

    Captures Model Context Protocol SSE connections and high-frequency
    agent API burst patterns that bypass traditional browser-level detection.

    Table: sat_mcp_discoveries
    """

    __tablename__ = "sat_mcp_discoveries"

    connection_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="mcp_sse | agent_api_burst | mcp_config_file",
    )
    destination_host: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Destination host where MCP connection was detected",
    )
    estimated_server_type: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
        comment="Estimated MCP server category: llm_provider | tool_server | autonomous_agent",
    )
    risk_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
        comment="Risk score (0.0-1.0) computed from endpoint registry and connection pattern",
    )
    parent_discovery_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the parent sat_discoveries record, if linked",
    )
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp of the first detected MCP connection",
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        comment="UTC timestamp of the most recent detected event",
    )
    connection_metadata: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        comment="Raw connection metadata: bytes_per_second, request_count_per_minute, etc.",
    )


# ---------------------------------------------------------------------------
# GAP-247: AI Endpoint Registry (platform-wide, not tenant-scoped)
# ---------------------------------------------------------------------------


class SatAiEndpointRegistry(Base):
    """Curated database of known AI tool API endpoints with metadata.

    Platform-wide reference data — not tenant-scoped. Loaded into memory
    at service startup for O(1) lookup during scanning and risk scoring.

    Table: sat_ai_endpoint_registry
    """

    __tablename__ = "sat_ai_endpoint_registry"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        comment="Registry entry UUID",
    )
    domain: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Domain pattern to match (e.g. api.openai.com)",
    )
    tool_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Human-readable tool name (e.g. ChatGPT Personal)",
    )
    vendor: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Vendor / company name (e.g. OpenAI)",
    )
    category: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="llm_chat | code_assistant | image_gen | agentic | other",
    )
    data_residency_regions: Mapped[list] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        comment="List of data residency regions (ISO 3166-1 alpha-2 codes + EU, US, Global)",
    )
    gdpr_compliant: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="True if the vendor has confirmed GDPR compliance",
    )
    hipaa_compliant: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
        comment="True if the vendor has a signed HIPAA BAA",
    )
    base_risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.5,
        comment="Platform-baseline risk score (0.0-1.0) before tenant-specific adjustment",
    )
    governed_alternative_hint: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Name of the AumOS governed alternative to suggest in nudges",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        comment="Inactive entries are excluded from scans and risk scoring",
    )
    data_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        comment="Incremented on each update for optimistic concurrency",
    )
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp of the last manual verification of this entry",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        comment="UTC timestamp of registry entry creation",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
        comment="UTC timestamp of most recent update",
    )


# ---------------------------------------------------------------------------
# GAP-248: User Coaching / Nudge Events
# ---------------------------------------------------------------------------


class SatNudgeEvent(AumOSModel):
    """Records of coaching nudges delivered to users via the browser extension.

    Tracks nudge delivery, dismissal, and whether the user clicked through to
    the governed alternative. Used to measure nudge effectiveness and
    behavioral change over time.

    Table: sat_nudge_events
    """

    __tablename__ = "sat_nudge_events"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="User UUID who received the nudge",
    )
    tool_domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
        comment="Domain of the shadow AI tool that triggered the nudge",
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Risk level that caused the nudge: critical | high | medium",
    )
    nudge_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="The coaching message delivered to the user",
    )
    governed_alternative: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        comment="Governed alternative tool name suggested in the nudge",
    )
    dismissed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if the user dismissed the nudge without clicking through",
    )
    clicked_alternative: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        comment="True if the user clicked the governed alternative link",
    )
    telemetry_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the sat_extension_telemetry record that triggered this nudge",
    )
