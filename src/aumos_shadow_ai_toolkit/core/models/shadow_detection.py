"""SQLAlchemy ORM models for P0.3 Shadow AI Detection and Amnesty Baseline.

These models sit alongside the existing sat_* models and use the same
AumOSModel base class (provides id, tenant_id, created_at, updated_at).

Tables:
  sat_shadow_detections      — network-traffic-based detection events
  sat_shadow_migration_proposals — AumOS module migration proposals per detection
  sat_amnesty_programs       — tenant amnesty program lifecycle records
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import DateTime, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aumos_common.database import AumOSModel


class ShadowAIDetection(AumOSModel):
    """A detection event from network traffic analysis.

    Records metadata (never content) of an employee communicating with an
    AI provider API outside approved enterprise channels. Sensitivity and risk
    scores are computed at detection time.

    Status lifecycle:
        detected -> reviewed -> migrated | approved | blocked

    Table: sat_shadow_detections
    """

    __tablename__ = "sat_shadow_detections"

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        comment="Source IP address (IPv4 or IPv6, max 45 chars for IPv6)",
    )
    destination_domain: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        index=True,
        comment="Destination AI provider domain detected in traffic",
    )
    provider: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Canonical AI provider identifier: openai, anthropic, google, cohere, etc.",
    )
    estimated_data_sensitivity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="low",
        comment="Estimated data sensitivity: low | medium | high | critical",
    )
    estimated_daily_cost_usd: Mapped[Decimal] = mapped_column(
        Numeric(8, 4),
        nullable=False,
        default=Decimal("0.0000"),
        comment="Estimated daily API cost in USD based on traffic volume heuristics",
    )
    compliance_risk_score: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=Decimal("0.00"),
        comment="Composite compliance risk score 0.00–100.00",
    )
    business_value_indicator: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="unknown",
        comment=(
            "Inferred business use: productivity | code-assist | analysis | "
            "text-generation | image-generation | data-analysis | unknown"
        ),
    )
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="detected",
        index=True,
        comment="Detection lifecycle: detected | reviewed | migrated | approved | blocked",
    )

    migration_proposals: Mapped[list["ShadowMigrationProposal"]] = relationship(
        "ShadowMigrationProposal",
        back_populates="detection",
        cascade="all, delete-orphan",
    )


class ShadowMigrationProposal(AumOSModel):
    """An AumOS module migration proposal generated for a shadow AI detection.

    Created by MigrationProposalService when a detection is reviewed. Maps
    the observed shadow AI usage pattern to the most appropriate AumOS module,
    estimating migration complexity and productivity preservation.

    Table: sat_shadow_migration_proposals
    """

    __tablename__ = "sat_shadow_migration_proposals"

    detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
        comment="Parent ShadowAIDetection UUID (no FK constraint — cross-service safe)",
    )
    proposed_aumos_module: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        comment="AumOS module to migrate to: aumos-llm-serving, aumos-text-engine, etc.",
    )
    migration_complexity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="moderate",
        comment="Migration effort category: trivial | moderate | complex",
    )
    estimated_migration_hours: Mapped[Decimal] = mapped_column(
        Numeric(5, 1),
        nullable=False,
        default=Decimal("8.0"),
        comment="Estimated developer hours to complete migration",
    )
    productivity_preservation_pct: Mapped[Decimal] = mapped_column(
        Numeric(5, 2),
        nullable=False,
        default=Decimal("90.00"),
        comment="Estimated percentage of current productivity retained post-migration (0–100)",
    )
    compliance_gain_description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
        comment="Human-readable description of compliance gains from migration",
    )

    detection: Mapped["ShadowAIDetection"] = relationship(
        "ShadowAIDetection",
        back_populates="migration_proposals",
    )


class AmnestyProgram(AumOSModel):
    """Tenant-scoped Shadow AI Amnesty Program lifecycle record.

    An amnesty program allows employees to continue using shadow AI tools
    during a grace period while migration proposals are prepared. After the
    grace period expires, governed-only enforcement activates.

    Status lifecycle:
        active -> grace_period -> enforcing
        active -> cancelled

    Table: sat_amnesty_programs
    """

    __tablename__ = "sat_amnesty_programs"

    notification_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Message sent to affected users when the amnesty program is initiated",
    )
    grace_period_days: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=30,
        comment="Number of days in the grace period before enforcement activates",
    )
    grace_period_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when the grace period expires and enforcement begins",
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="active",
        index=True,
        comment="Program lifecycle: active | grace_period | enforcing | cancelled",
    )
    affected_user_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of users with shadow AI detections at program initiation",
    )
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        comment="UUID of the admin user who initiated the amnesty program",
    )
    enforcement_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="UTC timestamp when governed-only enforcement became active",
    )
    cancellation_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Reason if program was cancelled before enforcement",
    )
