"""Pydantic request and response schemas for the P0.3 Shadow AI Detection API.

All API inputs and outputs are typed Pydantic models — never raw dicts.
Covers: detection listing, migration proposals, amnesty program management,
and network log submission for analysis.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Input models — network log ingestion
# ---------------------------------------------------------------------------


class DNSQuery(BaseModel):
    """A single DNS query metadata record from network monitoring.

    Content is never stored — only the queried domain and connection metadata.
    """

    queried_domain: str = Field(
        ...,
        max_length=253,
        description="The fully-qualified domain name that was queried",
        examples=["api.openai.com"],
    )
    source_ip: str = Field(
        ...,
        max_length=45,
        description="Source IP address of the DNS query (IPv4 or IPv6)",
        examples=["192.168.1.100"],
    )
    queried_at: datetime = Field(
        ...,
        description="UTC timestamp when the DNS query was made",
    )
    has_auth_header: bool = Field(
        default=False,
        description="Whether the subsequent HTTP request contained an Authorization or API-key header",
    )


class NetworkLogEntry(BaseModel):
    """A single network log entry from a proxy, NGFW, or SIEM feed.

    Records only connection metadata — no request or response content.
    """

    source_ip: str = Field(
        ...,
        max_length=45,
        description="Source IP address",
    )
    destination_domain: str = Field(
        ...,
        max_length=500,
        description="Destination domain extracted from TLS SNI or HTTP Host header",
        examples=["api.anthropic.com"],
    )
    url_path: str | None = Field(
        default=None,
        max_length=2048,
        description="URL path if available from HTTP CONNECT or DPI (no query string)",
        examples=["/v1/messages"],
    )
    request_size_bytes: int = Field(
        default=0,
        ge=0,
        description="Estimated request payload size in bytes (metadata only)",
    )
    has_auth_header: bool = Field(
        default=False,
        description="Whether an Authorization or X-Api-Key header was observed",
    )
    observed_at: datetime = Field(
        ...,
        description="UTC timestamp when the connection was observed",
    )
    protocol: str = Field(
        default="https",
        description="Protocol: https | http | tcp",
    )


class NetworkLogSubmission(BaseModel):
    """Batch of network log entries submitted for shadow AI analysis."""

    tenant_id: uuid.UUID = Field(
        ...,
        description="Tenant UUID scoping this submission",
    )
    log_entries: list[NetworkLogEntry] = Field(
        ...,
        min_length=1,
        max_length=10_000,
        description="Network log entries to analyse for shadow AI usage",
    )
    submission_period_start: datetime | None = Field(
        default=None,
        description="Start of the log capture window (UTC)",
    )
    submission_period_end: datetime | None = Field(
        default=None,
        description="End of the log capture window (UTC)",
    )

    @model_validator(mode="after")
    def validate_period_order(self) -> "NetworkLogSubmission":
        """Ensure period_start is before period_end if both are provided."""
        if (
            self.submission_period_start is not None
            and self.submission_period_end is not None
            and self.submission_period_start >= self.submission_period_end
        ):
            raise ValueError("submission_period_start must be before submission_period_end")
        return self


# ---------------------------------------------------------------------------
# Detection schemas
# ---------------------------------------------------------------------------


class ShadowAIDetectionResponse(BaseModel):
    """Response schema for a single shadow AI detection event."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    source_ip: str
    destination_domain: str
    provider: str
    estimated_data_sensitivity: str
    estimated_daily_cost_usd: Decimal
    compliance_risk_score: Decimal
    business_value_indicator: str
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DetectionListResponse(BaseModel):
    """Paginated list of shadow AI detection events."""

    items: list[ShadowAIDetectionResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


class AnalyzeNetworkLogsResponse(BaseModel):
    """Response after submitting network logs for shadow AI analysis."""

    detections_found: int = Field(
        description="Number of shadow AI detections identified in the submitted logs"
    )
    providers_detected: list[str] = Field(
        description="Canonical provider identifiers found in the submission"
    )
    highest_risk_score: Decimal = Field(
        description="Highest compliance risk score observed (0.00–100.00)"
    )
    detections: list[ShadowAIDetectionResponse] = Field(
        description="Full detection details for each identified shadow AI usage"
    )


# ---------------------------------------------------------------------------
# Migration proposal schemas
# ---------------------------------------------------------------------------


class MigrationProposalResponse(BaseModel):
    """Response schema for a shadow AI migration proposal."""

    id: uuid.UUID
    tenant_id: uuid.UUID
    detection_id: uuid.UUID
    proposed_aumos_module: str
    migration_complexity: str
    estimated_migration_hours: Decimal
    productivity_preservation_pct: Decimal
    compliance_gain_description: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ProposeMigrationResponse(BaseModel):
    """Response after requesting a migration proposal for a detection."""

    detection_id: uuid.UUID
    proposal: MigrationProposalResponse


# ---------------------------------------------------------------------------
# Amnesty program schemas
# ---------------------------------------------------------------------------


class AmnestyInitiateRequest(BaseModel):
    """Request body to initiate the Shadow AI Amnesty Program."""

    notification_message: str = Field(
        ...,
        min_length=10,
        max_length=5000,
        description=(
            "Message sent to affected employees explaining the amnesty program, "
            "the migration path, and the grace period timeline."
        ),
        examples=[
            "We have identified unauthorized AI tool usage in your environment. "
            "During the next 30 days, please work with your IT team to migrate to "
            "the approved AumOS platform. Continued use will be restricted after this period."
        ],
    )
    grace_period_days: int = Field(
        default=30,
        ge=1,
        le=180,
        description="Number of days before governed-only enforcement activates (1–180)",
    )


class AmnestyInitiateResponse(BaseModel):
    """Response after initiating the Shadow AI Amnesty Program."""

    program_id: uuid.UUID
    tenant_id: uuid.UUID
    status: str
    affected_users_count: int = Field(
        description="Number of users with detected shadow AI usage at program initiation"
    )
    estimated_migrations_count: int = Field(
        description="Total number of migration proposals to be generated"
    )
    grace_period_days: int
    grace_period_expires_at: datetime
    created_at: datetime


class AmnestyStatusResponse(BaseModel):
    """Current status of a tenant's Shadow AI Amnesty Program."""

    tenant_id: uuid.UUID
    program_id: uuid.UUID | None
    status: str = Field(
        description="Program status: none | active | grace_period | enforcing | cancelled"
    )
    grace_period_days: int
    grace_period_expires_at: datetime | None
    affected_user_count: int
    is_active: bool
    enforcement_started_at: datetime | None


# ---------------------------------------------------------------------------
# Risk and migration aggregate schemas
# ---------------------------------------------------------------------------


class RiskSummary(BaseModel):
    """Aggregated risk summary for a set of shadow AI detections."""

    total_detections: int
    critical_count: int = Field(description="Detections with risk score >= 75")
    high_count: int = Field(description="Detections with risk score 50–74")
    medium_count: int = Field(description="Detections with risk score 25–49")
    low_count: int = Field(description="Detections with risk score < 25")
    providers: list[str] = Field(description="Distinct AI providers detected")
    average_risk_score: Decimal
    highest_risk_score: Decimal
    estimated_total_daily_cost_usd: Decimal


class MigrationSummaryResponse(BaseModel):
    """Aggregated migration effort summary for a set of detections."""

    total_detections: int
    total_estimated_hours: Decimal
    complexity_breakdown: dict[str, int] = Field(
        description="Count of proposals by complexity tier: {trivial, moderate, complex}"
    )
    module_breakdown: dict[str, int] = Field(
        description="Count of proposals per AumOS target module"
    )
    average_preservation_pct: Decimal = Field(
        description="Mean estimated productivity preservation percentage after migration"
    )
    proposals: list[MigrationProposalResponse]
