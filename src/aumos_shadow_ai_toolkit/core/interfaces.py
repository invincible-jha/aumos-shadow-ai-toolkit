"""Abstract interfaces (Protocol classes) for the AumOS Shadow AI Toolkit.

All adapters implement these protocols so services depend only on abstractions,
enabling straightforward testing via mock implementations.
"""

import uuid
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# NEW: Adapter interface protocols added for domain-specific adapters
# ---------------------------------------------------------------------------

from aumos_shadow_ai_toolkit.core.models import (
    MigrationPlan,
    ScanResult,
    ShadowAIDiscovery,
    UsageMetric,
)


@runtime_checkable
class IDiscoveryRepository(Protocol):
    """Persistence interface for ShadowAIDiscovery entities."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        detection_method: str,
        detected_user_id: uuid.UUID | None,
        scan_result_id: uuid.UUID | None,
    ) -> ShadowAIDiscovery:
        """Create and persist a new shadow AI discovery.

        Args:
            tenant_id: Owning tenant UUID.
            tool_name: Human-readable name of the detected AI tool.
            api_endpoint: Detected API domain/endpoint.
            detection_method: How the tool was detected.
            detected_user_id: Optional UUID of the employee detected.
            scan_result_id: Optional UUID of the scan that found it.

        Returns:
            Newly created ShadowAIDiscovery in detected status.
        """
        ...

    async def get_by_id(
        self, discovery_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> ShadowAIDiscovery | None:
        """Retrieve a discovery by UUID within a tenant.

        Args:
            discovery_id: Discovery UUID.
            tenant_id: Requesting tenant for RLS enforcement.

        Returns:
            ShadowAIDiscovery or None if not found.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
        status: str | None,
        risk_level: str | None,
    ) -> tuple[list[ShadowAIDiscovery], int]:
        """List discoveries for a tenant with pagination and optional filters.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.
            status: Optional status filter.
            risk_level: Optional risk level filter.

        Returns:
            Tuple of (discoveries, total_count).
        """
        ...

    async def update_status(
        self,
        discovery_id: uuid.UUID,
        status: str,
        dismissed_reason: str | None,
    ) -> ShadowAIDiscovery:
        """Update the status of a discovery.

        Args:
            discovery_id: Discovery UUID.
            status: New status value.
            dismissed_reason: Reason if status is dismissed.

        Returns:
            Updated ShadowAIDiscovery.
        """
        ...

    async def update_risk_assessment(
        self,
        discovery_id: uuid.UUID,
        risk_score: float,
        risk_level: str,
        data_sensitivity: str,
        compliance_exposure: list[str],
        risk_details: dict[str, Any],
    ) -> ShadowAIDiscovery:
        """Persist risk assessment results on a discovery.

        Args:
            discovery_id: Discovery UUID.
            risk_score: Composite risk score (0.0–1.0).
            risk_level: Severity string (critical/high/medium/low).
            data_sensitivity: Estimated data sensitivity category.
            compliance_exposure: List of compliance frameworks at risk.
            risk_details: Detailed breakdown from RiskAssessorService.

        Returns:
            Updated ShadowAIDiscovery with risk data.
        """
        ...

    async def find_existing(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        detected_user_id: uuid.UUID | None,
    ) -> ShadowAIDiscovery | None:
        """Find an existing discovery for the same tool and user.

        Used to update counters on re-detection rather than creating duplicates.

        Args:
            tenant_id: Owning tenant UUID.
            tool_name: AI tool name.
            detected_user_id: Employee UUID (or None for unknown user).

        Returns:
            Existing ShadowAIDiscovery or None if first detection.
        """
        ...

    async def increment_request_count(
        self,
        discovery_id: uuid.UUID,
        request_count_delta: int,
        estimated_volume_kb_delta: int,
        last_seen_at: datetime,
    ) -> ShadowAIDiscovery:
        """Increment request count and data volume on re-detection.

        Args:
            discovery_id: Discovery UUID.
            request_count_delta: Number of new requests detected.
            estimated_volume_kb_delta: Additional estimated data volume in KB.
            last_seen_at: Timestamp of the latest detection.

        Returns:
            Updated ShadowAIDiscovery with incremented counters.
        """
        ...


@runtime_checkable
class IMigrationRepository(Protocol):
    """Persistence interface for MigrationPlan entities."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        discovery_id: uuid.UUID,
        employee_id: uuid.UUID,
        shadow_tool_name: str,
        governed_tool_name: str,
        governed_model_id: uuid.UUID | None,
        migration_steps: list[dict[str, Any]],
        expires_at: datetime,
    ) -> MigrationPlan:
        """Create a new migration plan.

        Args:
            tenant_id: Owning tenant UUID.
            discovery_id: Parent shadow AI discovery UUID.
            employee_id: Employee being migrated.
            shadow_tool_name: Name of the unauthorized tool.
            governed_tool_name: Name of the governed alternative.
            governed_model_id: Optional model registry UUID.
            migration_steps: Ordered list of steps with completion status.
            expires_at: UTC expiry timestamp.

        Returns:
            Newly created MigrationPlan in pending status.
        """
        ...

    async def get_by_id(
        self, plan_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> MigrationPlan | None:
        """Retrieve a migration plan by UUID.

        Args:
            plan_id: MigrationPlan UUID.
            tenant_id: Requesting tenant.

        Returns:
            MigrationPlan or None if not found.
        """
        ...

    async def list_by_discovery(
        self, discovery_id: uuid.UUID, tenant_id: uuid.UUID
    ) -> list[MigrationPlan]:
        """List all migration plans for a discovery.

        Args:
            discovery_id: Parent discovery UUID.
            tenant_id: Requesting tenant.

        Returns:
            List of MigrationPlan instances.
        """
        ...

    async def update_status(
        self,
        plan_id: uuid.UUID,
        status: str,
        completed_at: datetime | None,
        notes: str | None,
    ) -> MigrationPlan:
        """Update the status of a migration plan.

        Args:
            plan_id: MigrationPlan UUID.
            status: New status value.
            completed_at: Optional completion timestamp.
            notes: Optional free-text notes.

        Returns:
            Updated MigrationPlan.
        """
        ...

    async def set_approval_workflow_id(
        self, plan_id: uuid.UUID, approval_workflow_id: uuid.UUID
    ) -> None:
        """Set the approval workflow ID after migration approval is initiated.

        Args:
            plan_id: MigrationPlan UUID.
            approval_workflow_id: Approval workflow UUID from aumos-approval-workflow.
        """
        ...


@runtime_checkable
class IScanResultRepository(Protocol):
    """Persistence interface for ScanResult entities."""

    async def create(
        self,
        tenant_id: uuid.UUID,
        scan_type: str,
        scan_parameters: dict[str, Any],
    ) -> ScanResult:
        """Create a scan result record to track a scan execution.

        Args:
            tenant_id: Owning tenant UUID.
            scan_type: scheduled | manual | triggered.
            scan_parameters: Parameters for this scan execution.

        Returns:
            Newly created ScanResult in running status.
        """
        ...

    async def complete(
        self,
        scan_id: uuid.UUID,
        new_discoveries_count: int,
        total_endpoints_checked: int,
        duration_seconds: int,
    ) -> ScanResult:
        """Mark a scan as completed with result statistics.

        Args:
            scan_id: ScanResult UUID.
            new_discoveries_count: Number of new discoveries found.
            total_endpoints_checked: Total endpoints scanned.
            duration_seconds: Scan duration in seconds.

        Returns:
            Updated ScanResult with status=completed.
        """
        ...

    async def fail(
        self, scan_id: uuid.UUID, error_message: str
    ) -> ScanResult:
        """Mark a scan as failed with an error message.

        Args:
            scan_id: ScanResult UUID.
            error_message: Error detail.

        Returns:
            Updated ScanResult with status=failed.
        """
        ...

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
    ) -> tuple[list[ScanResult], int]:
        """List scan results for a tenant with pagination.

        Args:
            tenant_id: Requesting tenant.
            page: 1-based page number.
            page_size: Results per page.

        Returns:
            Tuple of (scan_results, total_count).
        """
        ...


@runtime_checkable
class IUsageMetricRepository(Protocol):
    """Persistence interface for UsageMetric entities."""

    async def upsert_daily(
        self,
        tenant_id: uuid.UUID,
        period_start: datetime,
        period_end: datetime,
        metrics: dict[str, Any],
    ) -> UsageMetric:
        """Upsert daily usage metrics for a tenant.

        Args:
            tenant_id: Owning tenant UUID.
            period_start: Start of the daily period (UTC).
            period_end: End of the daily period (UTC).
            metrics: Metric values to set/update.

        Returns:
            Upserted UsageMetric for the period.
        """
        ...

    async def get_dashboard_stats(
        self,
        tenant_id: uuid.UUID,
        days: int,
    ) -> dict[str, Any]:
        """Retrieve dashboard statistics for the last N days.

        Args:
            tenant_id: Requesting tenant.
            days: Number of days to include in the aggregation.

        Returns:
            Dict with totals, trends, top tools, and breach cost estimates.
        """
        ...


@runtime_checkable
class INetworkScannerAdapter(Protocol):
    """Interface for the network traffic analysis adapter."""

    async def scan(
        self,
        tenant_id: uuid.UUID,
        endpoints_to_check: list[str],
        timeout_seconds: int,
    ) -> list[dict[str, Any]]:
        """Perform a network scan to detect shadow AI API calls.

        Analyses network metadata only — never reads request/response content.
        Detects AI API usage via DNS patterns, TLS SNI, and HTTP CONNECT tunnels.

        Args:
            tenant_id: Owning tenant UUID (for scoping network namespace).
            endpoints_to_check: List of known AI API domain patterns.
            timeout_seconds: Maximum seconds to run the scan.

        Returns:
            List of detection dicts:
            [{tool_name, api_endpoint, detection_method, detected_user_id,
              request_count, estimated_volume_kb, first_seen_at, last_seen_at}]
        """
        ...


@runtime_checkable
class IGovernanceEngineAdapter(Protocol):
    """Interface for the governance engine risk policy adapter."""

    async def evaluate_risk(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        detection_metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Evaluate risk policy for a detected shadow AI tool.

        Calls the governance engine to determine data sensitivity, compliance
        exposure, and additional risk factors based on tenant policy.

        Args:
            tenant_id: Requesting tenant UUID.
            tool_name: Name of the detected AI tool.
            api_endpoint: Detected API endpoint.
            detection_metadata: Metadata from the network scan.

        Returns:
            Risk assessment dict:
            {risk_score, risk_level, data_sensitivity, compliance_exposure, details}
        """
        ...


# ---------------------------------------------------------------------------
# Domain-specific adapter protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class IShadowAIRiskScorer(Protocol):
    """Interface for the composite risk scoring adapter."""

    async def score_discovery(
        self,
        discovery_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        data_types: list[str],
        compliance_frameworks: list[str],
        request_count: int,
        estimated_volume_kb: int,
    ) -> dict[str, Any]:
        """Compute a composite risk score for a shadow AI discovery.

        Args:
            discovery_id: Discovery UUID being scored.
            tool_name: Name of the detected AI tool.
            api_endpoint: Detected API endpoint domain.
            data_types: List of inferred data type categories.
            compliance_frameworks: Applicable compliance frameworks (GDPR, HIPAA, etc.).
            request_count: Total detected request count.
            estimated_volume_kb: Estimated data volume in kilobytes.

        Returns:
            Risk score dict with composite_score, risk_level, and dimension breakdown.
        """
        ...

    async def score_batch(
        self,
        discoveries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Score multiple discoveries in a single pass.

        Args:
            discoveries: List of discovery attribute dicts (same keys as score_discovery).

        Returns:
            List of risk score dicts in the same order as input.
        """
        ...

    async def get_tool_risk_breakdown(
        self,
        tool_name: str,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Return aggregated risk breakdown for a tool across a tenant's discoveries.

        Args:
            tool_name: AI tool name.
            tenant_id: Scoping tenant UUID.

        Returns:
            Aggregated risk breakdown dict with dimension scores and discovery count.
        """
        ...


@runtime_checkable
class IShadowAIReportGenerator(Protocol):
    """Interface for generating executive and operational compliance reports."""

    async def generate_executive_summary(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        migration_plans: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate an executive-level shadow AI risk summary.

        Args:
            tenant_id: Requesting tenant UUID.
            discoveries: List of discovery data dicts.
            migration_plans: List of migration plan data dicts.

        Returns:
            Executive summary dict with risk highlights and cost exposure.
        """
        ...

    async def generate_discovery_report(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate a detailed per-tool discovery findings report.

        Args:
            tenant_id: Requesting tenant UUID.
            discoveries: List of discovery data dicts.

        Returns:
            Discovery report dict with per-tool findings and risk details.
        """
        ...

    async def export_as_json(
        self,
        tenant_id: uuid.UUID,
        report_type: str,
    ) -> str:
        """Export a report as a JSON string.

        Args:
            tenant_id: Requesting tenant UUID.
            report_type: Report type identifier (executive | discovery | migration).

        Returns:
            JSON-serialized report string.
        """
        ...


@runtime_checkable
class IShadowUsageAnalytics(Protocol):
    """Interface for shadow AI usage analytics computations."""

    async def get_api_call_volume(
        self,
        tenant_id: uuid.UUID,
        days: int,
    ) -> dict[str, Any]:
        """Return API call volume metrics for the specified window.

        Args:
            tenant_id: Requesting tenant UUID.
            days: Reporting window in days.

        Returns:
            Volume metrics dict with daily breakdown and top tools.
        """
        ...

    async def get_user_adoption_patterns(
        self,
        tenant_id: uuid.UUID,
        days: int,
    ) -> dict[str, Any]:
        """Return user adoption patterns for shadow AI tools.

        Args:
            tenant_id: Requesting tenant UUID.
            days: Reporting window in days.

        Returns:
            Adoption pattern dict with per-tool user counts and growth trends.
        """
        ...

    async def get_department_aggregation(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Return shadow AI usage aggregated by department.

        Args:
            tenant_id: Requesting tenant UUID.

        Returns:
            Department aggregation dict with usage counts and risk exposure.
        """
        ...

    async def get_dashboard_data(
        self,
        tenant_id: uuid.UUID,
        days: int,
    ) -> dict[str, Any]:
        """Return a combined analytics payload for the usage dashboard.

        Args:
            tenant_id: Requesting tenant UUID.
            days: Reporting window in days.

        Returns:
            Dashboard data dict combining volume, adoption, trends, and departments.
        """
        ...


@runtime_checkable
class IShadowCostEstimator(Protocol):
    """Interface for shadow AI tool cost estimation and TCO comparison."""

    async def estimate_shadow_tool_cost(
        self,
        tool_name: str,
        user_count: int,
        monthly_api_calls: int,
    ) -> dict[str, Any]:
        """Estimate the annual cost of a shadow AI tool deployment.

        Args:
            tool_name: Name of the shadow AI tool.
            user_count: Number of detected users.
            monthly_api_calls: Estimated monthly API call volume.

        Returns:
            Shadow tool cost estimate dict with licensing, API, and hidden costs.
        """
        ...

    async def compute_tco_comparison(
        self,
        tool_name: str,
        managed_alternative: str,
        user_count: int,
        monthly_api_calls: int,
    ) -> dict[str, Any]:
        """Compute a 3-year TCO comparison between shadow and managed alternatives.

        Args:
            tool_name: Shadow AI tool name.
            managed_alternative: Managed alternative name.
            user_count: Number of users.
            monthly_api_calls: Monthly API call volume.

        Returns:
            TCO comparison dict with year-over-year cost projections and savings.
        """
        ...

    async def identify_savings_opportunities(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identify the highest-value savings opportunities across all shadow tools.

        Args:
            tenant_id: Requesting tenant UUID.
            discoveries: List of discovery data dicts.

        Returns:
            Prioritized list of savings opportunity dicts.
        """
        ...


@runtime_checkable
class IShadowComplianceChecker(Protocol):
    """Interface for shadow AI regulatory and policy compliance assessment."""

    async def assess_discovery(
        self,
        discovery_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        data_types: list[str],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Assess the compliance risk for a single shadow AI discovery.

        Args:
            discovery_id: Discovery UUID being assessed.
            tool_name: AI tool name.
            api_endpoint: Detected API endpoint domain.
            data_types: Inferred data type categories.
            tenant_id: Requesting tenant UUID.

        Returns:
            Compliance assessment dict with framework violations and remediations.
        """
        ...

    async def check_framework_mapping(
        self,
        data_types: list[str],
        applicable_frameworks: list[str],
    ) -> dict[str, Any]:
        """Map data types and tool usage to regulatory framework violations.

        Args:
            data_types: List of data type categories.
            applicable_frameworks: Frameworks to evaluate (GDPR, HIPAA, SOX, etc.).

        Returns:
            Framework mapping dict with violation severity per framework.
        """
        ...

    async def generate_compliance_report(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate a portfolio-level compliance report for all shadow discoveries.

        Args:
            tenant_id: Requesting tenant UUID.
            discoveries: List of discovery data dicts.

        Returns:
            Compliance report dict with aggregate violations, remediations, and scores.
        """
        ...
