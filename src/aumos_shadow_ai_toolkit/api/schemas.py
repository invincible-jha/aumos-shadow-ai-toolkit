"""Pydantic request and response schemas for the Shadow AI Toolkit API.

All API inputs and outputs are typed Pydantic models — never raw dicts.
"""

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Discovery schemas
# ---------------------------------------------------------------------------


class ShadowAIDiscoveryResponse(BaseModel):
    """Response schema for a shadow AI discovery."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    tool_name: str
    api_endpoint: str
    detection_method: str
    detected_user_id: uuid.UUID | None
    risk_score: float
    risk_level: str
    data_sensitivity: str
    compliance_exposure: list[str]
    status: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    request_count: int
    estimated_data_volume_kb: int
    scan_result_id: uuid.UUID | None
    risk_details: dict[str, Any]
    dismissed_reason: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DiscoveryListResponse(BaseModel):
    """Paginated list of shadow AI discoveries."""

    items: list[ShadowAIDiscoveryResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# Scan schemas
# ---------------------------------------------------------------------------


class ScanInitiateRequest(BaseModel):
    """Request body for initiating a network scan."""

    scan_type: str = Field(
        default="manual",
        pattern="^(manual|scheduled|triggered)$",
        description="Type of scan: manual | scheduled | triggered",
    )


class ScanResultResponse(BaseModel):
    """Response schema for a scan result."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    scan_type: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: int | None
    new_discoveries_count: int
    total_endpoints_checked: int
    error_message: str | None
    scan_parameters: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Risk report schema
# ---------------------------------------------------------------------------


class RiskLevelCounts(BaseModel):
    """Counts of discoveries by risk level."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0


class TopRiskEntry(BaseModel):
    """A single top-risk discovery entry."""

    discovery_id: uuid.UUID
    tool_name: str
    risk_score: float
    risk_level: str
    compliance_exposure: list[str]


class RiskReportResponse(BaseModel):
    """Aggregated risk assessment report for a tenant."""

    total_discoveries: int
    by_risk_level: RiskLevelCounts
    estimated_breach_cost_usd: float = Field(
        description="Estimated financial exposure in USD based on $4.63M breach cost benchmark"
    )
    top_risks: list[TopRiskEntry]
    generated_at: datetime


# ---------------------------------------------------------------------------
# Migration schemas
# ---------------------------------------------------------------------------


class MigrationStartRequest(BaseModel):
    """Request body for starting a migration workflow."""

    governed_tool_name: str = Field(
        ...,
        min_length=2,
        max_length=255,
        description="Name of the sanctioned governed AI tool to migrate to",
        examples=["AumOS Enterprise AI Assistant"],
    )
    governed_model_id: uuid.UUID | None = Field(
        default=None,
        description="Optional UUID reference to the model in aumos-model-registry",
    )
    employee_id: uuid.UUID | None = Field(
        default=None,
        description="Employee UUID to migrate (defaults to detected user from discovery)",
    )


class MigrationStepResponse(BaseModel):
    """Response schema for a single migration step."""

    step: str
    status: str


class MigrationPlanResponse(BaseModel):
    """Response schema for a migration plan."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    discovery_id: uuid.UUID
    employee_id: uuid.UUID
    shadow_tool_name: str
    governed_tool_name: str
    governed_model_id: uuid.UUID | None
    status: str
    approval_workflow_id: uuid.UUID | None
    migration_steps: list[dict[str, Any]]
    expires_at: datetime | None
    completed_at: datetime | None
    notes: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Dashboard schema
# ---------------------------------------------------------------------------


class DashboardTrendPoint(BaseModel):
    """A single data point in a usage trend series."""

    date: str
    count: int
    risk_level: str


class DashboardTopTool(BaseModel):
    """A top shadow AI tool entry in the dashboard."""

    tool_name: str
    count: int
    risk_level: str
    active_users: int


class DashboardResponse(BaseModel):
    """Usage analytics dashboard response."""

    period_days: int
    total_discoveries: int
    active_users: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    migrations_started: int
    migrations_completed: int
    estimated_breach_cost_usd: float
    top_tools: list[DashboardTopTool]
    trend: list[DashboardTrendPoint]
    generated_at: datetime


# ---------------------------------------------------------------------------
# GAP-244: Browser extension telemetry schemas
# ---------------------------------------------------------------------------


class ExtensionTelemetryRequest(BaseModel):
    """Navigation event metadata from the AumOS Shadow AI Detector browser extension.

    Content is NEVER included — only tool domain, session duration estimate,
    and extension metadata.
    """

    tool_domain: str = Field(
        ...,
        max_length=255,
        description="Domain navigated to (e.g. chat.openai.com)",
        examples=["chat.openai.com"],
    )
    tool_name: str = Field(
        ...,
        max_length=255,
        description="Human-readable tool name resolved from domain registry",
        examples=["ChatGPT Personal"],
    )
    session_duration_seconds: int | None = Field(
        default=None,
        description="Estimated session duration from tab visibility API (seconds)",
    )
    extension_version: str = Field(
        ...,
        max_length=50,
        description="Extension semantic version string",
        examples=["1.2.0"],
    )
    browser_family: Literal["chrome", "edge", "firefox"] = Field(
        ...,
        description="Browser family that sent the event",
    )
    timestamp_utc: datetime = Field(
        ...,
        description="UTC timestamp of the navigation event",
    )


class ExtensionTelemetryResponse(BaseModel):
    """Response to a browser extension telemetry ingest request."""

    telemetry_id: uuid.UUID = Field(description="UUID of the persisted telemetry record")
    risk_level: Literal["critical", "high", "medium", "low"] = Field(
        description="Immediate risk classification for the navigated tool"
    )
    governed_alternative: str | None = Field(
        default=None,
        description="Name of the governed AumOS alternative, if available",
    )
    nudge_message: str | None = Field(
        default=None,
        description="Coaching message to display to the user; None if nudging is disabled or risk is low",
    )


# ---------------------------------------------------------------------------
# GAP-245: Real-time proxy event schemas
# ---------------------------------------------------------------------------


class ProxyConnectionEventRequest(BaseModel):
    """Inbound event from a forward proxy (Squid / Zscaler / NGFW).

    Sent by corporate network proxies that detect HTTPS traffic to known
    AI API endpoints in real time.
    """

    tenant_id: uuid.UUID = Field(description="Tenant scope for this proxy event")
    destination_host: str = Field(
        ...,
        max_length=255,
        description="Destination hostname observed by the proxy (e.g. api.openai.com)",
    )
    destination_port: int = Field(default=443, description="Destination TCP port")
    source_ip: str = Field(
        ...,
        max_length=45,
        description="Internal source IP address (anonymised — used only for identity resolution, never stored)",
    )
    protocol: Literal["CONNECT", "HTTPS", "HTTP"] = Field(
        description="Layer-7 protocol observed by the proxy"
    )
    bytes_sent: int | None = Field(default=None, description="Bytes sent by client in this connection")
    event_timestamp: datetime = Field(description="UTC timestamp of the proxy event")
    proxy_source: str = Field(
        ...,
        max_length=100,
        description="Identifier of the proxy that sent the event (e.g. squid, zscaler, palo_alto)",
    )


class ProxyEventAcceptedResponse(BaseModel):
    """202 Accepted response for proxy webhook events."""

    status: str = Field(default="accepted", description="Always 'accepted'")
    event_id: uuid.UUID = Field(description="UUID assigned to this proxy event")


# ---------------------------------------------------------------------------
# GAP-246: MCP discovery schemas
# ---------------------------------------------------------------------------


class McpDiscoveryResponse(BaseModel):
    """Response schema for a detected MCP server connection or agent API burst."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    connection_type: str
    destination_host: str
    estimated_server_type: str | None
    risk_score: float | None
    parent_discovery_id: uuid.UUID | None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class McpDiscoveryListResponse(BaseModel):
    """Paginated list of MCP discoveries."""

    items: list[McpDiscoveryResponse]
    total: int
    page: int
    page_size: int


# ---------------------------------------------------------------------------
# GAP-247: AI Endpoint Registry schemas
# ---------------------------------------------------------------------------


class AiEndpointRegistryResponse(BaseModel):
    """A single entry in the curated AI endpoint registry."""

    id: uuid.UUID
    domain: str
    tool_name: str
    vendor: str
    category: str
    data_residency_regions: list[str]
    gdpr_compliant: bool | None
    hipaa_compliant: bool | None
    base_risk_score: float
    governed_alternative_hint: str | None
    is_active: bool
    data_version: int
    last_verified_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AiEndpointRegistryListResponse(BaseModel):
    """Paginated list of AI endpoint registry entries."""

    items: list[AiEndpointRegistryResponse]
    total: int
    page: int
    page_size: int


class AiEndpointUpsertRequest(BaseModel):
    """Request to create or update an AI endpoint registry entry."""

    tool_name: str = Field(..., max_length=255)
    vendor: str = Field(..., max_length=255)
    category: Literal["llm_chat", "code_assistant", "image_gen", "agentic", "other"]
    data_residency_regions: list[str] = Field(default_factory=list)
    gdpr_compliant: bool | None = None
    hipaa_compliant: bool | None = None
    base_risk_score: float = Field(default=0.5, ge=0.0, le=1.0)
    governed_alternative_hint: str | None = None
    is_active: bool = True
