"""Cost estimation adapter for shadow AI vs. managed alternative comparison.

Implements ShadowCostEstimator which models total cost of ownership for
shadow AI tool usage and produces ROI projections for migrating to a
governed managed alternative. Covers per-user licensing, API spend,
security incident overhead, compliance costs, and support burden.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Annual per-seat consumer plan prices for common shadow AI tools (USD).
_TOOL_SEAT_COST_ANNUAL_USD: dict[str, float] = {
    "ChatGPT / OpenAI API": 240.0,
    "Claude.ai / Anthropic API": 240.0,
    "Perplexity AI": 240.0,
    "Google Gemini": 240.0,
    "Cohere": 312.0,
    "Mistral AI": 180.0,
    "Together AI": 360.0,
    "Replicate": 480.0,
    "Hugging Face": 120.0,
    "Groq": 180.0,
}

_DEFAULT_TOOL_SEAT_COST_USD: float = 200.0

# Security/compliance overhead as a multiple of base licence cost.
# Represents IT time, legal review, audit prep, and potential incident response.
_SHADOW_TCO_OVERHEAD_MULTIPLIER: float = 2.5
_MANAGED_TCO_OVERHEAD_MULTIPLIER: float = 1.15

# Average security incident cost attributed to a single shadow AI exposure (USD).
_AVG_INCIDENT_COST_USD: float = 4_630_000.0  # IBM Cost of a Data Breach 2024

# Probability of an incident materialising per critical discovery per year.
_INCIDENT_PROBABILITY_CRITICAL: float = 0.05
_INCIDENT_PROBABILITY_HIGH: float = 0.02
_INCIDENT_PROBABILITY_MEDIUM: float = 0.005

# Compliance fine exposure per un-remediated framework violation (USD/year).
_COMPLIANCE_FINE_EXPOSURE_USD: dict[str, float] = {
    "GDPR": 20_000_000.0,
    "HIPAA": 1_900_000.0,
    "PCI_DSS": 100_000.0,
    "CCPA": 7_500.0,
    "SOX": 5_000_000.0,
    "SOC2": 0.0,
    "ISO_27001": 0.0,
    "NIST": 0.0,
}


class ShadowCostEstimator:
    """Model and compare costs between shadow AI tooling and a managed alternative.

    Produces line-item cost breakdowns covering:
    - Per-user licensing / API spend for shadow tools
    - Security incident probability-weighted exposure
    - Compliance fine risk
    - IT support and governance overhead
    - Managed alternative TCO
    - Net savings and ROI projection over 1–3 years

    All monetary amounts are in USD.
    """

    def __init__(
        self,
        managed_tool_name: str = "AumOS Enterprise AI",
        managed_annual_seat_cost_usd: float = 1_800.0,
        organisation_name: str = "Enterprise",
    ) -> None:
        """Initialise the cost estimator.

        Args:
            managed_tool_name: Display name of the governed managed alternative.
            managed_annual_seat_cost_usd: Annual per-seat cost of the managed tool.
            organisation_name: Organisation name for report metadata.
        """
        self._managed_tool_name = managed_tool_name
        self._managed_seat_cost = managed_annual_seat_cost_usd
        self._org_name = organisation_name

    async def estimate_shadow_tool_cost(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        user_count: int,
        api_calls_per_user_monthly: int = 0,
        risk_level: str = "medium",
        compliance_frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """Estimate the full annual cost of a single shadow AI tool deployment.

        Includes base licensing, estimated API spend, security incident
        probability-weighted exposure, and compliance fine risk.

        Args:
            tenant_id: Tenant UUID for audit context.
            tool_name: Shadow AI tool name.
            user_count: Number of affected employees.
            api_calls_per_user_monthly: Average monthly API calls per user.
            risk_level: Risk level from risk scorer (critical | high | medium | low).
            compliance_frameworks: List of at-risk regulatory frameworks.

        Returns:
            Cost breakdown dict with line items and total annual cost estimate.
        """
        base_seat_cost = (
            _TOOL_SEAT_COST_ANNUAL_USD.get(tool_name, _DEFAULT_TOOL_SEAT_COST_USD) * user_count
        )

        # API overage estimate: assume $0.002 per 1 000 tokens, ~500 tokens/call.
        api_overage = (
            api_calls_per_user_monthly * user_count * 12 * 0.001
        )

        # Security incident probability-weighted cost.
        incident_probability = {
            "critical": _INCIDENT_PROBABILITY_CRITICAL,
            "high": _INCIDENT_PROBABILITY_HIGH,
            "medium": _INCIDENT_PROBABILITY_MEDIUM,
            "low": 0.001,
        }.get(risk_level, 0.001)
        incident_exposure = _AVG_INCIDENT_COST_USD * incident_probability

        # Compliance fine risk (capped at 2 % of total, annualised).
        frameworks = compliance_frameworks or []
        compliance_exposure = sum(
            _COMPLIANCE_FINE_EXPOSURE_USD.get(f, 0.0) * 0.001  # 0.1% chance of max fine
            for f in frameworks
        )

        # IT overhead: $500/user/year for unmanaged tools (security reviews, help desk).
        it_overhead = 500.0 * user_count

        total_annual = base_seat_cost + api_overage + incident_exposure + compliance_exposure + it_overhead

        logger.info(
            "Shadow tool cost estimated",
            tenant_id=str(tenant_id),
            tool_name=tool_name,
            user_count=user_count,
            total_annual_usd=round(total_annual),
        )

        return {
            "tool_name": tool_name,
            "user_count": user_count,
            "annual_cost_breakdown": {
                "base_seat_licensing_usd": round(base_seat_cost, 2),
                "api_overage_usd": round(api_overage, 2),
                "security_incident_exposure_usd": round(incident_exposure, 2),
                "compliance_fine_risk_usd": round(compliance_exposure, 2),
                "it_support_overhead_usd": round(it_overhead, 2),
            },
            "total_annual_cost_usd": round(total_annual, 2),
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def estimate_managed_alternative_cost(
        self,
        tenant_id: uuid.UUID,
        user_count: int,
        include_implementation_cost: bool = True,
    ) -> dict[str, Any]:
        """Estimate the annual TCO for the managed governed alternative.

        Args:
            tenant_id: Tenant UUID.
            user_count: Number of seats to licence.
            include_implementation_cost: Whether to amortise a one-time
                implementation cost over 3 years.

        Returns:
            Managed tool cost breakdown dict.
        """
        base_licence = self._managed_seat_cost * user_count
        support_overhead = base_licence * (_MANAGED_TCO_OVERHEAD_MULTIPLIER - 1.0)

        # One-time implementation: ~$50 000 base + $500 per user, amortised over 3 years.
        implementation_annual = 0.0
        implementation_one_time = 0.0
        if include_implementation_cost:
            implementation_one_time = 50_000.0 + 500.0 * user_count
            implementation_annual = implementation_one_time / 3.0

        total_annual = base_licence + support_overhead + implementation_annual

        return {
            "managed_tool_name": self._managed_tool_name,
            "user_count": user_count,
            "annual_cost_breakdown": {
                "base_licence_usd": round(base_licence, 2),
                "support_and_governance_overhead_usd": round(support_overhead, 2),
                "implementation_amortised_usd": round(implementation_annual, 2),
            },
            "one_time_implementation_usd": round(implementation_one_time, 2),
            "total_annual_tco_usd": round(total_annual, 2),
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def compute_tco_comparison(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        employee_count: int = 100,
    ) -> dict[str, Any]:
        """Compare full TCO between shadow and managed tooling portfolios.

        Iterates over all discovered tools, sums their costs, and compares
        against the managed alternative for the same user population.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts including tool_name, risk_level,
                detected_user_id, and compliance_exposure.
            employee_count: Total employees in scope.

        Returns:
            TCO comparison dict with line items, savings, and ROI.
        """
        tool_user_counts: dict[str, set[str]] = {}
        tool_risk_levels: dict[str, str] = {}
        tool_compliance: dict[str, list[str]] = {}

        for discovery in discoveries:
            tool = discovery.get("tool_name", "unknown")
            user_id = str(discovery.get("detected_user_id", ""))
            risk = discovery.get("risk_level", "medium")
            frameworks = discovery.get("compliance_exposure", [])

            tool_user_counts.setdefault(tool, set())
            if user_id:
                tool_user_counts[tool].add(user_id)
            tool_risk_levels[tool] = risk  # Keep last/highest seen.
            existing = tool_compliance.get(tool, [])
            tool_compliance[tool] = list(dict.fromkeys(existing + frameworks))

        affected_users = len({
            str(d.get("detected_user_id", ""))
            for d in discoveries
            if d.get("detected_user_id")
        }) or max(1, employee_count // 10)

        shadow_line_items: list[dict[str, Any]] = []
        shadow_total = 0.0

        for tool, users in tool_user_counts.items():
            user_count = len(users) or 1
            cost_result = await self.estimate_shadow_tool_cost(
                tenant_id=tenant_id,
                tool_name=tool,
                user_count=user_count,
                risk_level=tool_risk_levels.get(tool, "medium"),
                compliance_frameworks=tool_compliance.get(tool, []),
            )
            shadow_total += cost_result["total_annual_cost_usd"]
            shadow_line_items.append(
                {
                    "tool": tool,
                    "users": user_count,
                    "annual_cost_usd": cost_result["total_annual_cost_usd"],
                }
            )

        managed_result = await self.estimate_managed_alternative_cost(
            tenant_id=tenant_id,
            user_count=affected_users,
        )
        managed_total = managed_result["total_annual_tco_usd"]

        net_annual_savings = shadow_total - managed_total
        roi_pct = (net_annual_savings / managed_total * 100.0) if managed_total > 0 else 0.0

        logger.info(
            "TCO comparison complete",
            tenant_id=str(tenant_id),
            shadow_total_usd=round(shadow_total),
            managed_total_usd=round(managed_total),
            net_savings_usd=round(net_annual_savings),
        )

        return {
            "shadow_portfolio": {
                "tool_count": len(shadow_line_items),
                "affected_users": affected_users,
                "annual_tco_usd": round(shadow_total, 2),
                "line_items": shadow_line_items,
            },
            "managed_alternative": {
                "tool_name": self._managed_tool_name,
                "user_count": affected_users,
                "annual_tco_usd": managed_total,
                "breakdown": managed_result["annual_cost_breakdown"],
            },
            "net_annual_savings_usd": round(net_annual_savings, 2),
            "roi_pct": round(roi_pct, 1),
            "payback_period_months": self._compute_payback_months(
                managed_result["one_time_implementation_usd"],
                net_annual_savings,
            ),
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def project_savings(
        self,
        tenant_id: uuid.UUID,
        annual_net_savings_usd: float,
        implementation_cost_usd: float = 0.0,
        years: int = 3,
        growth_rate_pct: float = 0.10,
    ) -> dict[str, Any]:
        """Project net savings over a multi-year horizon.

        Applies an annual growth rate to model increasing shadow AI adoption
        (and therefore increasing savings from migration) over time.

        Args:
            tenant_id: Tenant UUID.
            annual_net_savings_usd: Year-1 net savings USD.
            implementation_cost_usd: One-time migration implementation cost.
            years: Projection horizon.
            growth_rate_pct: Annual growth rate for shadow AI adoption (0.10 = 10%).

        Returns:
            Multi-year savings projection dict.
        """
        yearly_projections: list[dict[str, Any]] = []
        cumulative_savings = -implementation_cost_usd  # Start negative (upfront cost).
        cumulative_savings_pv = -implementation_cost_usd

        # Discount rate for NPV calculation.
        discount_rate = 0.08

        for year in range(1, years + 1):
            savings = annual_net_savings_usd * ((1 + growth_rate_pct) ** (year - 1))
            cumulative_savings += savings
            # Present value (discounted).
            pv_factor = 1.0 / ((1 + discount_rate) ** year)
            pv_savings = savings * pv_factor
            cumulative_savings_pv += pv_savings

            yearly_projections.append(
                {
                    "year": year,
                    "annual_savings_usd": round(savings, 2),
                    "pv_savings_usd": round(pv_savings, 2),
                    "cumulative_net_savings_usd": round(cumulative_savings, 2),
                    "cumulative_npv_usd": round(cumulative_savings_pv, 2),
                }
            )

        payback_months = self._compute_payback_months(implementation_cost_usd, annual_net_savings_usd)

        return {
            "implementation_cost_usd": round(implementation_cost_usd, 2),
            "year_1_annual_savings_usd": round(annual_net_savings_usd, 2),
            "growth_rate_pct": round(growth_rate_pct * 100, 1),
            "discount_rate_pct": round(discount_rate * 100, 1),
            "payback_period_months": payback_months,
            "yearly_projections": yearly_projections,
            "total_npv_usd": round(cumulative_savings_pv, 2),
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def identify_savings_opportunities(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Rank shadow tools by savings opportunity from migration.

        Returns tools in descending order of potential cost reduction,
        giving migration teams a prioritised action list.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts.

        Returns:
            List of opportunity dicts sorted by savings potential.
        """
        tool_costs: dict[str, float] = {}
        tool_users: dict[str, set[str]] = {}

        for discovery in discoveries:
            tool = discovery.get("tool_name", "unknown")
            user_id = str(discovery.get("detected_user_id", ""))
            tool_users.setdefault(tool, set())
            if user_id:
                tool_users[tool].add(user_id)

        opportunities: list[dict[str, Any]] = []
        for tool, users in tool_users.items():
            user_count = len(users) or 1
            shadow_cost = (
                _TOOL_SEAT_COST_ANNUAL_USD.get(tool, _DEFAULT_TOOL_SEAT_COST_USD)
                * user_count
                * _SHADOW_TCO_OVERHEAD_MULTIPLIER
            )
            managed_cost = self._managed_seat_cost * user_count * _MANAGED_TCO_OVERHEAD_MULTIPLIER
            savings = shadow_cost - managed_cost
            tool_costs[tool] = savings

            opportunities.append(
                {
                    "tool_name": tool,
                    "affected_users": user_count,
                    "shadow_annual_tco_usd": round(shadow_cost, 2),
                    "managed_annual_tco_usd": round(managed_cost, 2),
                    "annual_savings_usd": round(savings, 2),
                    "priority": "high" if savings > 50_000 else "medium" if savings > 10_000 else "low",
                }
            )

        opportunities.sort(key=lambda o: o["annual_savings_usd"], reverse=True)
        return opportunities

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _compute_payback_months(
        self, implementation_cost: float, annual_savings: float
    ) -> int:
        """Compute the breakeven payback period in months.

        Args:
            implementation_cost: One-time migration cost.
            annual_savings: Annual net savings after migration.

        Returns:
            Payback period in months (0 if implementation cost is zero).
        """
        if implementation_cost <= 0:
            return 0
        if annual_savings <= 0:
            return 999  # Never breaks even.
        return max(1, round((implementation_cost / annual_savings) * 12))
