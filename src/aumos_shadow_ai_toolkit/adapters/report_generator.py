"""Report generation adapter for shadow AI discovery and migration reports.

Implements ShadowAIReportGenerator which produces executive summaries,
per-tool discovery findings, migration readiness assessments, cost comparisons
between shadow and managed tooling, and risk reduction quantifications.

Reports are produced as structured dicts (JSON-serialisable). PDF generation
is noted as a downstream concern that would wrap these payloads.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Average industry breach cost per risk level (USD), based on IBM 2024 figures.
_BREACH_COST_PER_LEVEL: dict[str, int] = {
    "critical": 4_630_000,
    "high": 1_000_000,
    "medium": 250_000,
    "low": 50_000,
}

# Typical annual per-seat costs for common shadow AI tools (USD).
_SHADOW_TOOL_ANNUAL_COST_USD: dict[str, float] = {
    "ChatGPT / OpenAI API": 240.0,       # ChatGPT Plus $20/mo
    "Claude.ai / Anthropic API": 240.0,  # Claude Pro $20/mo
    "Perplexity AI": 240.0,              # Pro $20/mo
    "Google Gemini": 240.0,              # Advanced $20/mo
    "Cohere": 300.0,                     # Estimated API spend
    "Mistral AI": 180.0,                 # Estimated API spend
    "Together AI": 360.0,                # Estimated API spend
    "Replicate": 480.0,                  # Estimated API spend
    "Hugging Face": 120.0,               # Pro Hub
    "Groq": 180.0,                       # Estimated API spend
}

_DEFAULT_SHADOW_TOOL_COST_USD: float = 200.0   # Conservative fallback

# Managed/governed alternative cost (annual per seat, AumOS Enterprise).
_MANAGED_ALTERNATIVE_ANNUAL_COST_USD: float = 1_800.0  # $150/mo enterprise seat

# Additional TCO factors as multipliers on base licence cost.
_SHADOW_TCO_MULTIPLIER: float = 2.5    # Support, security incidents, compliance overhead
_MANAGED_TCO_MULTIPLIER: float = 1.15  # Lower overhead with full governance stack


class ShadowAIReportGenerator:
    """Generate discovery and migration reports for shadow AI governance.

    Produces three report types:

    1. Executive summary — board-level risk overview.
    2. Discovery report  — per-tool findings with risk scores and usage details.
    3. Migration report  — readiness assessment and cost/ROI projections.

    All methods return JSON-serialisable dicts. Callers are responsible for
    serialising to JSON or rendering as PDF.
    """

    def __init__(
        self,
        organisation_name: str = "Enterprise",
        managed_tool_name: str = "AumOS Enterprise AI",
        managed_annual_cost_per_seat: float = _MANAGED_ALTERNATIVE_ANNUAL_COST_USD,
        breach_cost_overrides: dict[str, int] | None = None,
    ) -> None:
        """Initialise the report generator.

        Args:
            organisation_name: Human-readable org name for report headers.
            managed_tool_name: Name of the governed managed alternative.
            managed_annual_cost_per_seat: Annual per-seat cost for managed tool.
            breach_cost_overrides: Optional override for breach cost per risk level.
        """
        self._org_name = organisation_name
        self._managed_tool_name = managed_tool_name
        self._managed_cost = managed_annual_cost_per_seat
        self._breach_costs = {**_BREACH_COST_PER_LEVEL, **(breach_cost_overrides or {})}

    async def generate_executive_summary(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        migration_plans: list[dict[str, Any]],
        report_period_days: int = 30,
    ) -> dict[str, Any]:
        """Generate a board-level executive summary of shadow AI risk.

        Args:
            tenant_id: Tenant UUID for scope.
            discoveries: List of discovery dicts (must include risk_level, tool_name,
                request_count, estimated_data_volume_kb).
            migration_plans: List of migration plan dicts (must include status).
            report_period_days: Number of days covered by this report.

        Returns:
            Executive summary dict with headline metrics and risk narrative.
        """
        risk_distribution = self._count_by_risk_level(discoveries)
        total_discoveries = len(discoveries)
        active_users = len({d.get("detected_user_id") for d in discoveries if d.get("detected_user_id")})

        estimated_exposure = sum(
            self._breach_costs.get(d.get("risk_level", "low"), 0)
            for d in discoveries
        )

        migration_stats = {
            "total": len(migration_plans),
            "pending": sum(1 for p in migration_plans if p.get("status") == "pending"),
            "in_progress": sum(1 for p in migration_plans if p.get("status") == "in_progress"),
            "completed": sum(1 for p in migration_plans if p.get("status") == "completed"),
        }
        migration_completion_rate = (
            migration_stats["completed"] / migration_stats["total"] * 100
            if migration_stats["total"] > 0
            else 0.0
        )

        top_tools = self._top_tools_by_risk(discoveries, limit=5)
        risk_narrative = self._compose_risk_narrative(
            total_discoveries, risk_distribution, estimated_exposure, active_users
        )

        logger.info(
            "Executive summary generated",
            tenant_id=str(tenant_id),
            total_discoveries=total_discoveries,
            estimated_exposure_usd=estimated_exposure,
        )

        return {
            "report_type": "executive_summary",
            "organisation": self._org_name,
            "tenant_id": str(tenant_id),
            "period_days": report_period_days,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "headline_metrics": {
                "total_shadow_ai_tools_detected": total_discoveries,
                "affected_employees": active_users,
                "estimated_breach_cost_exposure_usd": estimated_exposure,
                "critical_risk_tools": risk_distribution["critical"],
                "high_risk_tools": risk_distribution["high"],
            },
            "risk_distribution": risk_distribution,
            "migration_progress": {
                **migration_stats,
                "completion_rate_pct": round(migration_completion_rate, 1),
            },
            "top_risk_tools": top_tools,
            "risk_narrative": risk_narrative,
        }

    async def generate_discovery_report(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        include_raw_detections: bool = False,
    ) -> dict[str, Any]:
        """Generate a detailed per-tool discovery findings report.

        Args:
            tenant_id: Tenant UUID.
            discoveries: List of discovery dicts with full metadata.
            include_raw_detections: Whether to include raw detection metadata.

        Returns:
            Discovery report dict with per-tool findings and compliance exposure.
        """
        grouped = self._group_discoveries_by_tool(discoveries)
        tool_findings: list[dict[str, Any]] = []

        for tool_name, tool_discoveries in sorted(
            grouped.items(),
            key=lambda item: max(
                d.get("risk_score", 0.0) for d in item[1]
            ),
            reverse=True,
        ):
            highest_risk = max(tool_discoveries, key=lambda d: d.get("risk_score", 0.0))
            total_requests = sum(d.get("request_count", 0) for d in tool_discoveries)
            total_volume_kb = sum(d.get("estimated_data_volume_kb", 0) for d in tool_discoveries)
            unique_users = len({d.get("detected_user_id") for d in tool_discoveries if d.get("detected_user_id")})
            all_frameworks: list[str] = []
            for d in tool_discoveries:
                all_frameworks.extend(d.get("compliance_exposure", []))
            unique_frameworks = list(dict.fromkeys(all_frameworks))  # Preserve order, deduplicate.

            finding: dict[str, Any] = {
                "tool_name": tool_name,
                "api_endpoint": highest_risk.get("api_endpoint", ""),
                "detection_count": len(tool_discoveries),
                "affected_users": unique_users,
                "total_api_requests": total_requests,
                "total_estimated_volume_kb": total_volume_kb,
                "peak_risk_score": highest_risk.get("risk_score", 0.0),
                "risk_level": highest_risk.get("risk_level", "unknown"),
                "data_sensitivity": highest_risk.get("data_sensitivity", "unknown"),
                "compliance_frameworks_at_risk": unique_frameworks,
                "breach_cost_exposure_usd": self._breach_costs.get(
                    highest_risk.get("risk_level", "low"), 0
                ),
                "first_detected": min(
                    (d.get("first_seen_at") or d.get("created_at", "")) for d in tool_discoveries
                ),
                "last_detected": max(
                    (d.get("last_seen_at") or d.get("updated_at", "")) for d in tool_discoveries
                ),
                "discovery_ids": [str(d.get("id", "")) for d in tool_discoveries],
            }
            if include_raw_detections:
                finding["raw_detections"] = tool_discoveries
            tool_findings.append(finding)

        logger.info(
            "Discovery report generated",
            tenant_id=str(tenant_id),
            tool_count=len(grouped),
            total_discoveries=len(discoveries),
        )

        return {
            "report_type": "discovery_report",
            "organisation": self._org_name,
            "tenant_id": str(tenant_id),
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "summary": {
                "unique_tools_detected": len(grouped),
                "total_discovery_events": len(discoveries),
                "risk_distribution": self._count_by_risk_level(discoveries),
            },
            "tool_findings": tool_findings,
        }

    async def generate_migration_report(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        migration_plans: list[dict[str, Any]],
        employee_count: int = 100,
    ) -> dict[str, Any]:
        """Generate a migration readiness assessment and ROI projection.

        Computes shadow tool costs, managed alternative TCO, and projected
        savings from completing all open migrations.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts used for cost modelling.
            migration_plans: Migration plan dicts for progress tracking.
            employee_count: Total employees in scope for shadow AI monitoring.

        Returns:
            Migration report dict with readiness scores and cost projections.
        """
        cost_comparison = self._compute_cost_comparison(discoveries, employee_count)
        risk_reduction = self._quantify_risk_reduction(discoveries, migration_plans)
        readiness_score = self._compute_migration_readiness(discoveries, migration_plans)

        migration_timeline = self._estimate_migration_timeline(discoveries, migration_plans)

        logger.info(
            "Migration report generated",
            tenant_id=str(tenant_id),
            readiness_score=readiness_score,
            projected_savings_usd=cost_comparison.get("net_annual_savings_usd", 0),
        )

        return {
            "report_type": "migration_report",
            "organisation": self._org_name,
            "tenant_id": str(tenant_id),
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "migration_readiness": {
                "score_0_100": readiness_score,
                "grade": self._readiness_grade(readiness_score),
                "open_migrations": sum(
                    1 for p in migration_plans if p.get("status") in ("pending", "in_progress")
                ),
                "completed_migrations": sum(
                    1 for p in migration_plans if p.get("status") == "completed"
                ),
            },
            "cost_comparison": cost_comparison,
            "risk_reduction": risk_reduction,
            "estimated_migration_timeline_weeks": migration_timeline,
        }

    async def export_as_json(
        self, report: dict[str, Any], pretty: bool = True
    ) -> str:
        """Serialise a report dict to a JSON string.

        Args:
            report: Report dict to serialise.
            pretty: Whether to use indented formatting.

        Returns:
            JSON string representation of the report.
        """
        return json.dumps(report, indent=2 if pretty else None, default=str)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _count_by_risk_level(
        self, discoveries: list[dict[str, Any]]
    ) -> dict[str, int]:
        """Tally discoveries by risk level.

        Args:
            discoveries: List of discovery dicts.

        Returns:
            Dict with counts per level: critical, high, medium, low, unknown.
        """
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        for d in discoveries:
            level = d.get("risk_level", "unknown")
            counts[level] = counts.get(level, 0) + 1
        return counts

    def _top_tools_by_risk(
        self, discoveries: list[dict[str, Any]], limit: int = 5
    ) -> list[dict[str, Any]]:
        """Return the top N tools by peak risk score.

        Args:
            discoveries: Discovery dicts.
            limit: Maximum number of tools to return.

        Returns:
            List of dicts: {tool_name, risk_level, peak_score}.
        """
        grouped = self._group_discoveries_by_tool(discoveries)
        tool_peaks = [
            {
                "tool_name": tool,
                "risk_level": max(tool_discoveries, key=lambda d: d.get("risk_score", 0.0)).get(
                    "risk_level", "unknown"
                ),
                "peak_risk_score": max(d.get("risk_score", 0.0) for d in tool_discoveries),
            }
            for tool, tool_discoveries in grouped.items()
        ]
        return sorted(tool_peaks, key=lambda t: t["peak_risk_score"], reverse=True)[:limit]

    def _group_discoveries_by_tool(
        self, discoveries: list[dict[str, Any]]
    ) -> dict[str, list[dict[str, Any]]]:
        """Group discovery dicts by tool_name.

        Args:
            discoveries: Flat list of discovery dicts.

        Returns:
            Dict mapping tool_name to its discovery dicts.
        """
        grouped: dict[str, list[dict[str, Any]]] = {}
        for discovery in discoveries:
            tool = discovery.get("tool_name", "unknown")
            grouped.setdefault(tool, []).append(discovery)
        return grouped

    def _compose_risk_narrative(
        self,
        total: int,
        distribution: dict[str, int],
        exposure_usd: int,
        active_users: int,
    ) -> str:
        """Compose a plain-text risk narrative paragraph.

        Args:
            total: Total discovery count.
            distribution: Risk level counts.
            exposure_usd: Estimated breach cost exposure in USD.
            active_users: Number of affected employees.

        Returns:
            Risk narrative paragraph string.
        """
        critical = distribution.get("critical", 0)
        high = distribution.get("high", 0)
        severity = (
            "critical" if critical > 0 else "high" if high > 0 else "moderate"
        )
        return (
            f"Shadow AI analysis has identified {total} unauthorised AI tool instances "
            f"used by {active_users} employee(s) within the {self._org_name} environment. "
            f"The portfolio carries {severity} risk exposure, with {critical} critical "
            f"and {high} high-risk discoveries, representing an estimated "
            f"USD {exposure_usd:,} potential breach cost based on industry benchmarks. "
            f"Immediate remediation is recommended for all critical and high-risk items."
        )

    def _compute_cost_comparison(
        self, discoveries: list[dict[str, Any]], employee_count: int
    ) -> dict[str, Any]:
        """Compare shadow tool costs against a managed alternative TCO.

        Args:
            discoveries: Discovery dicts for affected users.
            employee_count: Total employees in scope.

        Returns:
            Cost comparison dict with shadow, managed, and net savings figures.
        """
        affected_users = len(
            {d.get("detected_user_id") for d in discoveries if d.get("detected_user_id")}
        ) or max(1, employee_count // 10)

        shadow_tools = self._group_discoveries_by_tool(discoveries)
        shadow_base = sum(
            _SHADOW_TOOL_ANNUAL_COST_USD.get(tool, _DEFAULT_SHADOW_TOOL_COST_USD) * affected_users
            for tool in shadow_tools
        )
        shadow_tco = shadow_base * _SHADOW_TCO_MULTIPLIER

        managed_base = self._managed_cost * affected_users
        managed_tco = managed_base * _MANAGED_TCO_MULTIPLIER

        net_savings = shadow_tco - managed_tco
        roi_pct = (net_savings / managed_tco * 100) if managed_tco > 0 else 0.0

        projections: list[dict[str, Any]] = []
        for year in range(1, 4):
            projections.append(
                {
                    "year": year,
                    "shadow_tco_usd": round(shadow_tco * year),
                    "managed_tco_usd": round(managed_tco * year),
                    "cumulative_savings_usd": round(net_savings * year),
                }
            )

        return {
            "affected_users": affected_users,
            "shadow_tools_count": len(shadow_tools),
            "shadow_annual_tco_usd": round(shadow_tco),
            "managed_annual_tco_usd": round(managed_tco),
            "net_annual_savings_usd": round(net_savings),
            "roi_pct": round(roi_pct, 1),
            "three_year_projections": projections,
            "managed_tool_name": self._managed_tool_name,
        }

    def _quantify_risk_reduction(
        self,
        discoveries: list[dict[str, Any]],
        migration_plans: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Quantify the risk reduction achievable through completing migrations.

        Args:
            discoveries: Discovery dicts.
            migration_plans: Migration plan dicts.

        Returns:
            Risk reduction dict with current and post-migration exposure estimates.
        """
        current_exposure = sum(
            self._breach_costs.get(d.get("risk_level", "low"), 0) for d in discoveries
        )
        completed_discovery_ids = {
            str(p.get("discovery_id"))
            for p in migration_plans
            if p.get("status") == "completed"
        }
        remaining = [
            d for d in discoveries
            if str(d.get("id", "")) not in completed_discovery_ids
        ]
        residual_exposure = sum(
            self._breach_costs.get(d.get("risk_level", "low"), 0) for d in remaining
        )
        reduction = current_exposure - residual_exposure
        reduction_pct = (reduction / current_exposure * 100) if current_exposure > 0 else 0.0

        return {
            "current_breach_cost_exposure_usd": current_exposure,
            "post_migration_exposure_usd": residual_exposure,
            "risk_reduction_usd": reduction,
            "risk_reduction_pct": round(reduction_pct, 1),
            "migrations_required_for_full_reduction": len(
                [p for p in migration_plans if p.get("status") != "completed"]
            ),
        }

    def _compute_migration_readiness(
        self,
        discoveries: list[dict[str, Any]],
        migration_plans: list[dict[str, Any]],
    ) -> int:
        """Compute a 0–100 migration readiness score.

        Score increases with completed migrations and decreases when many
        critical discoveries lack any migration plan.

        Args:
            discoveries: Discovery dicts.
            migration_plans: Migration plan dicts.

        Returns:
            Integer readiness score 0–100.
        """
        if not discoveries:
            return 100

        total = len(discoveries)
        covered = len({str(p.get("discovery_id")) for p in migration_plans})
        completed = sum(1 for p in migration_plans if p.get("status") == "completed")

        coverage_score = covered / total
        completion_score = completed / total if total > 0 else 0.0

        critical_without_plan = sum(
            1
            for d in discoveries
            if d.get("risk_level") == "critical"
            and str(d.get("id", "")) not in {str(p.get("discovery_id")) for p in migration_plans}
        )
        penalty = min(0.3, critical_without_plan * 0.05)

        raw = (coverage_score * 0.4 + completion_score * 0.6) - penalty
        return max(0, min(100, round(raw * 100)))

    def _readiness_grade(self, score: int) -> str:
        """Map a readiness score to a letter grade.

        Args:
            score: Integer 0–100.

        Returns:
            Letter grade string: A | B | C | D | F.
        """
        if score >= 90:
            return "A"
        if score >= 75:
            return "B"
        if score >= 60:
            return "C"
        if score >= 40:
            return "D"
        return "F"

    def _estimate_migration_timeline(
        self,
        discoveries: list[dict[str, Any]],
        migration_plans: list[dict[str, Any]],
    ) -> int:
        """Estimate weeks to complete all open migrations.

        Assumes 2 migrations per week for critical/high, 4 per week for
        medium/low, based on typical change management throughput.

        Args:
            discoveries: Discovery dicts.
            migration_plans: Migration plan dicts.

        Returns:
            Estimated weeks to completion.
        """
        open_plans = [
            p for p in migration_plans if p.get("status") in ("pending", "in_progress")
        ]
        unmigrated_critical = sum(
            1 for d in discoveries
            if d.get("risk_level") in ("critical", "high")
            and str(d.get("id", "")) not in {str(p.get("discovery_id")) for p in migration_plans}
        )
        unmigrated_medium = sum(
            1 for d in discoveries
            if d.get("risk_level") in ("medium", "low")
            and str(d.get("id", "")) not in {str(p.get("discovery_id")) for p in migration_plans}
        )

        critical_weeks = (len(open_plans) + unmigrated_critical + 1) // 2
        medium_weeks = (unmigrated_medium + 3) // 4
        return max(1, critical_weeks + medium_weeks)
