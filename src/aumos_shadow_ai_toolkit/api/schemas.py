"""Pydantic request and response schemas for the Shadow AI Toolkit API.

All API inputs and outputs are typed Pydantic models — never raw dicts.
"""

import uuid
from datetime import datetime
from typing import Any

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
