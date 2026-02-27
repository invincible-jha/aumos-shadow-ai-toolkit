"""Usage analytics adapter for shadow AI tool monitoring.

Implements ShadowUsageAnalytics which processes raw discovery and usage
metric records into dashboard-ready analytics payloads. Covers API call
volume per tool, user adoption patterns, peak usage time analysis,
data flow mapping, trend detection, department aggregation, and
dashboard-ready JSON export.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# Minimum call count difference (%) to classify a trend as "growing" or "shrinking".
_TREND_GROWTH_THRESHOLD: float = 0.10   # +10% = growing
_TREND_DECLINE_THRESHOLD: float = -0.10  # -10% = shrinking

# Hour buckets for peak-usage analysis (UTC).
_BUSINESS_HOURS_START: int = 8
_BUSINESS_HOURS_END: int = 18


class ShadowUsageAnalytics:
    """Analyse usage patterns for shadow AI discoveries.

    Converts raw discovery and usage metric records into structured analytics
    payloads consumed by the dashboard and reporting services. All computations
    are pure in-memory — no additional database calls are made.

    Typical usage::

        analytics = ShadowUsageAnalytics()
        dashboard_data = await analytics.get_dashboard_data(
            tenant_id=tenant_id,
            discoveries=discoveries,
            usage_metrics=usage_metrics,
        )
    """

    async def get_api_call_volume(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        days: int = 30,
    ) -> dict[str, Any]:
        """Compute API call volumes per shadow AI tool.

        Args:
            tenant_id: Tenant UUID for audit context.
            discoveries: List of discovery dicts with request_count and tool_name.
            days: Reporting window in days.

        Returns:
            Dict with per-tool API call volumes and totals.
        """
        per_tool: dict[str, dict[str, Any]] = {}
        total_calls = 0

        for discovery in discoveries:
            tool = discovery.get("tool_name", "unknown")
            calls = discovery.get("request_count", 0)
            volume_kb = discovery.get("estimated_data_volume_kb", 0)

            if tool not in per_tool:
                per_tool[tool] = {
                    "tool_name": tool,
                    "total_api_calls": 0,
                    "total_volume_kb": 0,
                    "discovery_count": 0,
                    "api_endpoint": discovery.get("api_endpoint", ""),
                    "risk_level": discovery.get("risk_level", "unknown"),
                }
            per_tool[tool]["total_api_calls"] += calls
            per_tool[tool]["total_volume_kb"] += volume_kb
            per_tool[tool]["discovery_count"] += 1
            total_calls += calls

        ranked = sorted(per_tool.values(), key=lambda t: t["total_api_calls"], reverse=True)

        logger.info(
            "API call volume computed",
            tenant_id=str(tenant_id),
            tool_count=len(per_tool),
            total_calls=total_calls,
            period_days=days,
        )

        return {
            "period_days": days,
            "total_api_calls": total_calls,
            "tool_count": len(per_tool),
            "per_tool": ranked,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def get_user_adoption_patterns(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyse employee adoption of shadow AI tools.

        Produces per-user and per-role breakdowns of shadow AI tool usage,
        identifying power users and department-level adoption spread.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts with detected_user_id and tool_name.

        Returns:
            Adoption pattern dict with per-user and aggregate statistics.
        """
        user_tools: dict[str, set[str]] = defaultdict(set)
        user_calls: dict[str, int] = defaultdict(int)
        anonymous_count = 0

        for discovery in discoveries:
            user_id = discovery.get("detected_user_id")
            tool = discovery.get("tool_name", "unknown")
            calls = discovery.get("request_count", 0)

            if user_id:
                user_key = str(user_id)
                user_tools[user_key].add(tool)
                user_calls[user_key] += calls
            else:
                anonymous_count += 1

        total_users = len(user_tools)
        power_users = [
            {
                "user_id": user_id,
                "tools_used": list(tools),
                "total_calls": user_calls[user_id],
                "tool_count": len(tools),
            }
            for user_id, tools in sorted(
                user_tools.items(), key=lambda item: user_calls[item[0]], reverse=True
            )[:10]
        ]

        multi_tool_users = sum(1 for tools in user_tools.values() if len(tools) > 1)
        avg_tools_per_user = (
            sum(len(tools) for tools in user_tools.values()) / total_users
            if total_users > 0
            else 0.0
        )

        logger.info(
            "User adoption patterns computed",
            tenant_id=str(tenant_id),
            identified_users=total_users,
            anonymous_detections=anonymous_count,
        )

        return {
            "total_identified_users": total_users,
            "anonymous_detections": anonymous_count,
            "multi_tool_users": multi_tool_users,
            "average_tools_per_user": round(avg_tools_per_user, 2),
            "power_users": power_users,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def get_peak_usage_analysis(
        self,
        tenant_id: uuid.UUID,
        usage_metrics: list[dict[str, Any]],
        days: int = 7,
    ) -> dict[str, Any]:
        """Identify peak usage periods across shadow AI tools.

        Buckets usage metrics into hourly time slots and identifies the
        busiest periods, distinguishing business hours from after-hours usage.

        Args:
            tenant_id: Tenant UUID.
            usage_metrics: Usage metric dicts with period_start and request_count.
            days: Analysis window in days.

        Returns:
            Peak usage analysis dict with hourly distribution and peak periods.
        """
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)
        hourly_calls: dict[int, int] = defaultdict(int)
        daily_calls: dict[str, int] = defaultdict(int)
        total_calls = 0
        business_hours_calls = 0
        after_hours_calls = 0

        for metric in usage_metrics:
            period_str = metric.get("period_start")
            if not period_str:
                continue
            if isinstance(period_str, str):
                try:
                    period_dt = datetime.fromisoformat(period_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
            elif isinstance(period_str, datetime):
                period_dt = period_str
            else:
                continue

            if period_dt < cutoff:
                continue

            calls = metric.get("total_requests", metric.get("request_count", 0))
            hour = period_dt.hour
            day_key = period_dt.strftime("%Y-%m-%d")

            hourly_calls[hour] += calls
            daily_calls[day_key] += calls
            total_calls += calls

            if _BUSINESS_HOURS_START <= hour < _BUSINESS_HOURS_END:
                business_hours_calls += calls
            else:
                after_hours_calls += calls

        peak_hour = max(hourly_calls, key=hourly_calls.get, default=0) if hourly_calls else 0
        peak_day = max(daily_calls, key=daily_calls.get, default="N/A") if daily_calls else "N/A"

        hourly_distribution = [
            {
                "hour_utc": hour,
                "label": f"{hour:02d}:00–{hour + 1:02d}:00 UTC",
                "call_count": hourly_calls.get(hour, 0),
                "is_business_hours": _BUSINESS_HOURS_START <= hour < _BUSINESS_HOURS_END,
            }
            for hour in range(24)
        ]

        logger.info(
            "Peak usage analysis complete",
            tenant_id=str(tenant_id),
            total_calls=total_calls,
            peak_hour=peak_hour,
            period_days=days,
        )

        return {
            "period_days": days,
            "total_calls": total_calls,
            "business_hours_calls": business_hours_calls,
            "after_hours_calls": after_hours_calls,
            "after_hours_pct": round(
                after_hours_calls / total_calls * 100 if total_calls > 0 else 0.0, 1
            ),
            "peak_hour_utc": peak_hour,
            "peak_day": peak_day,
            "hourly_distribution": hourly_distribution,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def get_data_flow_mapping(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Map the data flows from employees to shadow AI endpoints.

        Shows which external AI APIs receive data from the tenant environment,
        along with estimated volumes — without capturing any actual content.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts with api_endpoint, data_sensitivity,
                and estimated_data_volume_kb.

        Returns:
            Data flow map with endpoint-level volume and sensitivity breakdowns.
        """
        endpoint_flows: dict[str, dict[str, Any]] = {}

        for discovery in discoveries:
            endpoint = discovery.get("api_endpoint", "unknown")
            sensitivity = discovery.get("data_sensitivity", "unknown")
            volume_kb = discovery.get("estimated_data_volume_kb", 0)
            tool = discovery.get("tool_name", endpoint)

            if endpoint not in endpoint_flows:
                endpoint_flows[endpoint] = {
                    "api_endpoint": endpoint,
                    "tool_name": tool,
                    "total_volume_kb": 0,
                    "highest_data_sensitivity": "public",
                    "sensitivity_categories": set(),
                    "user_count": set(),
                    "risk_level": "low",
                }
            flow = endpoint_flows[endpoint]
            flow["total_volume_kb"] += volume_kb
            flow["sensitivity_categories"].add(sensitivity)
            if discovery.get("detected_user_id"):
                flow["user_count"].add(str(discovery["detected_user_id"]))
            # Keep highest sensitivity.
            sensitivity_rank = {
                "healthcare": 7, "pii": 6, "financial": 5, "ip": 4,
                "confidential": 3, "internal": 2, "public": 1, "unknown": 0,
            }
            current_rank = sensitivity_rank.get(flow["highest_data_sensitivity"], 0)
            new_rank = sensitivity_rank.get(sensitivity, 0)
            if new_rank > current_rank:
                flow["highest_data_sensitivity"] = sensitivity
            if discovery.get("risk_level") in ("critical", "high"):
                flow["risk_level"] = discovery["risk_level"]

        serialised_flows = [
            {
                **{k: v for k, v in flow.items() if k not in ("sensitivity_categories", "user_count")},
                "sensitivity_categories": list(flow["sensitivity_categories"]),
                "unique_users": len(flow["user_count"]),
                "total_volume_mb": round(flow["total_volume_kb"] / 1024, 2),
            }
            for flow in endpoint_flows.values()
        ]
        serialised_flows.sort(key=lambda f: f["total_volume_kb"], reverse=True)

        total_volume_kb = sum(f["total_volume_kb"] for f in endpoint_flows.values())

        return {
            "external_ai_endpoints": len(endpoint_flows),
            "total_estimated_volume_kb": total_volume_kb,
            "total_estimated_volume_mb": round(total_volume_kb / 1024, 2),
            "data_flows": serialised_flows,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def detect_usage_trends(
        self,
        tenant_id: uuid.UUID,
        current_metrics: list[dict[str, Any]],
        previous_metrics: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Detect growing or shrinking shadow AI usage trends.

        Compares two time periods (e.g., last 30 days vs. previous 30 days)
        at the per-tool level to classify trends.

        Args:
            tenant_id: Tenant UUID.
            current_metrics: Usage metrics for the current period.
            previous_metrics: Usage metrics for the previous comparable period.

        Returns:
            Trend dict with per-tool classifications and overall trend.
        """
        current_by_tool = self._aggregate_calls_by_tool(current_metrics)
        previous_by_tool = self._aggregate_calls_by_tool(previous_metrics)

        all_tools = set(current_by_tool) | set(previous_by_tool)
        tool_trends: list[dict[str, Any]] = []

        for tool in sorted(all_tools):
            current_calls = current_by_tool.get(tool, 0)
            previous_calls = previous_by_tool.get(tool, 0)

            if previous_calls == 0 and current_calls > 0:
                trend = "new"
                change_pct = 100.0
            elif current_calls == 0 and previous_calls > 0:
                trend = "disappeared"
                change_pct = -100.0
            elif previous_calls > 0:
                change_pct = (current_calls - previous_calls) / previous_calls
                if change_pct >= _TREND_GROWTH_THRESHOLD:
                    trend = "growing"
                elif change_pct <= _TREND_DECLINE_THRESHOLD:
                    trend = "shrinking"
                else:
                    trend = "stable"
            else:
                trend = "stable"
                change_pct = 0.0

            tool_trends.append(
                {
                    "tool_name": tool,
                    "current_period_calls": current_calls,
                    "previous_period_calls": previous_calls,
                    "change_pct": round(change_pct * 100, 1),
                    "trend": trend,
                }
            )

        growing = sum(1 for t in tool_trends if t["trend"] in ("growing", "new"))
        shrinking = sum(1 for t in tool_trends if t["trend"] in ("shrinking", "disappeared"))
        overall_trend = "growing" if growing > shrinking else "shrinking" if shrinking > growing else "stable"

        return {
            "overall_trend": overall_trend,
            "growing_tool_count": growing,
            "shrinking_tool_count": shrinking,
            "per_tool_trends": tool_trends,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def get_department_aggregation(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        user_department_map: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Aggregate shadow AI usage by department.

        Uses an optional user-to-department map. Unresolvable users are
        placed in the "unknown" department.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts.
            user_department_map: Optional dict mapping user UUID strings to department names.

        Returns:
            Department aggregation dict with per-department risk and usage metrics.
        """
        department_map = user_department_map or {}
        dept_data: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "total_api_calls": 0,
                "unique_tools": set(),
                "unique_users": set(),
                "risk_levels": [],
                "total_volume_kb": 0,
            }
        )

        for discovery in discoveries:
            user_id = str(discovery.get("detected_user_id", ""))
            dept = department_map.get(user_id, "unknown")
            calls = discovery.get("request_count", 0)
            tool = discovery.get("tool_name", "unknown")
            risk = discovery.get("risk_level", "unknown")
            volume_kb = discovery.get("estimated_data_volume_kb", 0)

            dept_data[dept]["total_api_calls"] += calls
            dept_data[dept]["unique_tools"].add(tool)
            if user_id:
                dept_data[dept]["unique_users"].add(user_id)
            dept_data[dept]["risk_levels"].append(risk)
            dept_data[dept]["total_volume_kb"] += volume_kb

        serialised = []
        for dept_name, data in sorted(
            dept_data.items(), key=lambda item: item[1]["total_api_calls"], reverse=True
        ):
            risk_levels = data["risk_levels"]
            dominant_risk = (
                "critical" if "critical" in risk_levels
                else "high" if "high" in risk_levels
                else "medium" if "medium" in risk_levels
                else "low"
            )
            serialised.append(
                {
                    "department": dept_name,
                    "total_api_calls": data["total_api_calls"],
                    "unique_tool_count": len(data["unique_tools"]),
                    "tools_in_use": list(data["unique_tools"]),
                    "unique_users": len(data["unique_users"]),
                    "dominant_risk_level": dominant_risk,
                    "total_volume_kb": data["total_volume_kb"],
                }
            )

        return {
            "department_count": len(serialised),
            "departments": serialised,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def get_dashboard_data(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
        usage_metrics: list[dict[str, Any]],
        days: int = 30,
    ) -> dict[str, Any]:
        """Produce a complete dashboard-ready analytics payload.

        Combines all analytics dimensions into a single JSON-serialisable
        dict suitable for the dashboard API endpoint.

        Args:
            tenant_id: Tenant UUID.
            discoveries: Discovery dicts.
            usage_metrics: Usage metric dicts.
            days: Reporting window.

        Returns:
            Aggregated dashboard data dict.
        """
        volume = await self.get_api_call_volume(tenant_id, discoveries, days)
        adoption = await self.get_user_adoption_patterns(tenant_id, discoveries)
        peak = await self.get_peak_usage_analysis(tenant_id, usage_metrics, days)
        data_flows = await self.get_data_flow_mapping(tenant_id, discoveries)

        risk_summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for d in discoveries:
            level = d.get("risk_level", "low")
            risk_summary[level] = risk_summary.get(level, 0) + 1

        logger.info(
            "Dashboard data assembled",
            tenant_id=str(tenant_id),
            period_days=days,
            tool_count=volume.get("tool_count", 0),
        )

        return {
            "period_days": days,
            "risk_summary": risk_summary,
            "api_call_volume": volume,
            "user_adoption": adoption,
            "peak_usage": peak,
            "data_flow_map": data_flows,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _aggregate_calls_by_tool(
        self, metrics: list[dict[str, Any]]
    ) -> dict[str, int]:
        """Sum API call counts keyed by tool name from usage metric dicts.

        Args:
            metrics: Usage metric dicts.

        Returns:
            Dict mapping tool_name to total call count.
        """
        totals: dict[str, int] = defaultdict(int)
        for metric in metrics:
            top_tools = metric.get("top_tools", [])
            for tool_entry in top_tools:
                tool = tool_entry.get("tool_name", "unknown")
                totals[tool] += tool_entry.get("count", 0)
        return dict(totals)
