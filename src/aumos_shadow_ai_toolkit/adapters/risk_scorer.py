"""Risk scoring adapter for shadow AI tool assessments.

Implements ShadowAIRiskScorer to produce composite risk scores (0–100)
from data sensitivity, compliance violation severity, usage frequency,
and unauthorised API risk factors. Scores are normalised to a 0.0–1.0
float for storage, multiplied by 100 for the integer representation
returned in report payloads.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from aumos_common.observability import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

# Data sensitivity weight (0.0–1.0). Higher means more dangerous.
_DATA_SENSITIVITY_WEIGHTS: dict[str, float] = {
    "pii": 1.0,
    "financial": 0.9,
    "healthcare": 0.95,
    "ip": 0.85,
    "confidential": 0.8,
    "internal": 0.5,
    "public": 0.1,
    "unknown": 0.6,
}

# Compliance framework violation severity weights.
_COMPLIANCE_SEVERITY_WEIGHTS: dict[str, float] = {
    "HIPAA": 1.0,
    "PCI_DSS": 0.95,
    "GDPR": 0.9,
    "CCPA": 0.8,
    "SOX": 0.75,
    "SOC2": 0.65,
    "ISO_27001": 0.55,
    "NIST": 0.5,
}

# Known high-risk AI endpoints that process data server-side.
_HIGH_RISK_ENDPOINTS: frozenset[str] = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "api.cohere.com",
        "api.together.xyz",
        "api.replicate.com",
    }
)

# Risk level bands (using 0.0–1.0 normalised scores).
_THRESHOLD_CRITICAL: float = 0.7
_THRESHOLD_HIGH: float = 0.5
_THRESHOLD_MEDIUM: float = 0.3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalise_request_frequency(request_count: int) -> float:
    """Map an absolute request count to a 0.0–1.0 frequency weight.

    Uses a logarithmic scale so that low-volume usage is not over-penalised
    while high-volume usage is still captured.

    Args:
        request_count: Total detected API calls.

    Returns:
        Frequency weight in range [0.0, 1.0].
    """
    import math

    if request_count <= 0:
        return 0.0
    # log10(1)=0, log10(100)=2, log10(10000)=4 → normalise to cap at 1.0 at 10 000 calls.
    raw = math.log10(max(1, request_count)) / 4.0
    return min(1.0, raw)


def _classify_risk_level(score: float) -> str:
    """Convert a normalised risk score to a categorical risk level.

    Args:
        score: Composite risk score in range [0.0, 1.0].

    Returns:
        Risk level string: critical | high | medium | low.
    """
    if score >= _THRESHOLD_CRITICAL:
        return "critical"
    if score >= _THRESHOLD_HIGH:
        return "high"
    if score >= _THRESHOLD_MEDIUM:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------


class ShadowAIRiskScorer:
    """Compute composite risk scores for discovered shadow AI tools.

    Produces a 0–100 integer risk score and a categorical risk level for
    each discovery by combining:

    - Data sensitivity (what category of data the tool likely processes)
    - Compliance violation severity (which regulatory frameworks are at risk)
    - Usage frequency (request count weighted logarithmically)
    - Unauthorised API risk (whether the endpoint sends data to a third-party server)

    The score is also decomposed into per-dimension breakdowns for reporting.
    """

    def __init__(
        self,
        sensitivity_weight: float = 0.35,
        compliance_weight: float = 0.30,
        frequency_weight: float = 0.20,
        api_risk_weight: float = 0.15,
    ) -> None:
        """Initialise the risk scorer with dimension weights.

        The four weights must sum to 1.0. Defaults reflect typical
        enterprise AI governance priorities.

        Args:
            sensitivity_weight: Weight for data sensitivity dimension.
            compliance_weight: Weight for compliance violation severity dimension.
            frequency_weight: Weight for usage frequency dimension.
            api_risk_weight: Weight for unauthorised API endpoint risk dimension.
        """
        total = sensitivity_weight + compliance_weight + frequency_weight + api_risk_weight
        if abs(total - 1.0) > 0.001:
            raise ValueError(
                f"Risk scorer weights must sum to 1.0, got {total:.3f}"
            )
        self._sensitivity_weight = sensitivity_weight
        self._compliance_weight = compliance_weight
        self._frequency_weight = frequency_weight
        self._api_risk_weight = api_risk_weight

    async def score_discovery(
        self,
        tenant_id: uuid.UUID,
        tool_name: str,
        api_endpoint: str,
        data_sensitivity: str,
        compliance_frameworks: list[str],
        request_count: int,
        estimated_volume_kb: int,
        detection_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compute the composite risk score for a single shadow AI discovery.

        Args:
            tenant_id: Owning tenant UUID (used for audit logging).
            tool_name: Human-readable name of the detected tool.
            api_endpoint: Detected API domain (e.g., api.openai.com).
            data_sensitivity: Category of data at risk (pii | financial | ip | ...).
            compliance_frameworks: Regulatory frameworks at risk (GDPR, HIPAA, ...).
            request_count: Total detected API calls.
            estimated_volume_kb: Estimated data volume transferred in kilobytes.
            detection_metadata: Optional additional metadata from the network scanner.

        Returns:
            Dict with keys:
                score_0_100 (int): Composite risk score 0–100.
                normalised_score (float): Score in range 0.0–1.0.
                risk_level (str): critical | high | medium | low.
                breakdown (dict): Per-dimension component scores.
                computed_at (str): ISO-8601 UTC timestamp.
        """
        sensitivity_score = self._score_data_sensitivity(data_sensitivity)
        compliance_score = self._score_compliance_exposure(compliance_frameworks)
        frequency_score = _normalise_request_frequency(request_count)
        api_risk_score = self._score_api_endpoint_risk(api_endpoint, estimated_volume_kb)

        composite = (
            sensitivity_score * self._sensitivity_weight
            + compliance_score * self._compliance_weight
            + frequency_score * self._frequency_weight
            + api_risk_score * self._api_risk_weight
        )
        composite = min(1.0, max(0.0, composite))

        risk_level = _classify_risk_level(composite)
        score_int = round(composite * 100)

        breakdown = {
            "data_sensitivity": {
                "category": data_sensitivity,
                "raw_score": round(sensitivity_score, 4),
                "weighted_contribution": round(sensitivity_score * self._sensitivity_weight, 4),
            },
            "compliance_exposure": {
                "frameworks": compliance_frameworks,
                "raw_score": round(compliance_score, 4),
                "weighted_contribution": round(compliance_score * self._compliance_weight, 4),
            },
            "usage_frequency": {
                "request_count": request_count,
                "estimated_volume_kb": estimated_volume_kb,
                "raw_score": round(frequency_score, 4),
                "weighted_contribution": round(frequency_score * self._frequency_weight, 4),
            },
            "api_risk": {
                "endpoint": api_endpoint,
                "is_high_risk_endpoint": api_endpoint in _HIGH_RISK_ENDPOINTS,
                "raw_score": round(api_risk_score, 4),
                "weighted_contribution": round(api_risk_score * self._api_risk_weight, 4),
            },
        }

        logger.info(
            "Risk score computed",
            tenant_id=str(tenant_id),
            tool_name=tool_name,
            score=score_int,
            risk_level=risk_level,
            sensitivity_score=round(sensitivity_score, 3),
            compliance_score=round(compliance_score, 3),
        )

        return {
            "score_0_100": score_int,
            "normalised_score": round(composite, 6),
            "risk_level": risk_level,
            "breakdown": breakdown,
            "computed_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    async def score_batch(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Score multiple discoveries in a single call.

        Each element of ``discoveries`` must contain the keyword arguments
        accepted by :meth:`score_discovery` (excluding ``tenant_id``).

        Args:
            tenant_id: Owning tenant UUID.
            discoveries: List of discovery parameter dicts.

        Returns:
            List of score result dicts, one per input discovery,
            in the same order.
        """
        results: list[dict[str, Any]] = []
        for discovery in discoveries:
            result = await self.score_discovery(
                tenant_id=tenant_id,
                tool_name=discovery.get("tool_name", "unknown"),
                api_endpoint=discovery.get("api_endpoint", ""),
                data_sensitivity=discovery.get("data_sensitivity", "unknown"),
                compliance_frameworks=discovery.get("compliance_frameworks", []),
                request_count=discovery.get("request_count", 0),
                estimated_volume_kb=discovery.get("estimated_volume_kb", 0),
                detection_metadata=discovery.get("detection_metadata"),
            )
            result["tool_name"] = discovery.get("tool_name", "unknown")
            results.append(result)

        logger.info(
            "Batch risk scoring complete",
            tenant_id=str(tenant_id),
            discovery_count=len(discoveries),
            critical_count=sum(1 for r in results if r["risk_level"] == "critical"),
            high_count=sum(1 for r in results if r["risk_level"] == "high"),
        )
        return results

    async def get_tool_risk_breakdown(
        self,
        tenant_id: uuid.UUID,
        discoveries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce a per-tool risk breakdown across all discoveries.

        Aggregates discovery scores by tool name to show which tools
        present the highest cumulative risk to the tenant.

        Args:
            tenant_id: Owning tenant UUID.
            discoveries: List of scored discovery dicts (output of score_batch).

        Returns:
            Dict with keys:
                per_tool (dict): tool_name → {count, avg_score, max_score, risk_level}.
                overall_risk_distribution (dict): counts per risk level.
                generated_at (str): ISO-8601 UTC timestamp.
        """
        per_tool: dict[str, dict[str, Any]] = {}

        for discovery in discoveries:
            tool = discovery.get("tool_name", "unknown")
            score = discovery.get("normalised_score", 0.0)
            if tool not in per_tool:
                per_tool[tool] = {
                    "count": 0,
                    "total_score": 0.0,
                    "max_score": 0.0,
                    "risk_levels": [],
                }
            per_tool[tool]["count"] += 1
            per_tool[tool]["total_score"] += score
            per_tool[tool]["max_score"] = max(per_tool[tool]["max_score"], score)
            per_tool[tool]["risk_levels"].append(discovery.get("risk_level", "low"))

        tool_summaries: dict[str, dict[str, Any]] = {}
        for tool, data in per_tool.items():
            count = data["count"]
            avg_score = data["total_score"] / count if count > 0 else 0.0
            tool_summaries[tool] = {
                "discovery_count": count,
                "average_score": round(avg_score, 4),
                "max_score": round(data["max_score"], 4),
                "average_score_0_100": round(avg_score * 100),
                "dominant_risk_level": _classify_risk_level(data["max_score"]),
            }

        risk_distribution: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for discovery in discoveries:
            level = discovery.get("risk_level", "low")
            if level in risk_distribution:
                risk_distribution[level] += 1

        return {
            "per_tool": tool_summaries,
            "overall_risk_distribution": risk_distribution,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Private scoring helpers
    # ------------------------------------------------------------------

    def _score_data_sensitivity(self, data_sensitivity: str) -> float:
        """Return a sensitivity score for the given data category.

        Args:
            data_sensitivity: Data category string.

        Returns:
            Sensitivity score in range [0.0, 1.0].
        """
        return _DATA_SENSITIVITY_WEIGHTS.get(data_sensitivity.lower(), 0.6)

    def _score_compliance_exposure(self, frameworks: list[str]) -> float:
        """Aggregate compliance violation severity across applicable frameworks.

        Uses the maximum single-framework score combined with a diminishing
        multi-framework penalty to avoid double-counting.

        Args:
            frameworks: List of regulatory framework names at risk.

        Returns:
            Compliance score in range [0.0, 1.0].
        """
        if not frameworks:
            return 0.0
        scores = [
            _COMPLIANCE_SEVERITY_WEIGHTS.get(f.upper(), 0.4)
            for f in frameworks
        ]
        max_score = max(scores)
        # Each additional framework adds 5 % of remaining headroom.
        extra = sum(
            (1.0 - max_score) * 0.05 * (idx + 1)
            for idx, s in enumerate(sorted(scores[1:], reverse=True))
        )
        return min(1.0, max_score + extra)

    def _score_api_endpoint_risk(
        self, api_endpoint: str, estimated_volume_kb: int
    ) -> float:
        """Score the risk of data exfiltration via the detected API endpoint.

        High-risk endpoints (known to process prompt data server-side) receive
        a higher base score. Volume amplifies the score.

        Args:
            api_endpoint: Detected API domain.
            estimated_volume_kb: Estimated data volume transferred in kilobytes.

        Returns:
            API risk score in range [0.0, 1.0].
        """
        base = 0.8 if api_endpoint in _HIGH_RISK_ENDPOINTS else 0.4
        # Volume modifier: each 10 MB adds 5 %, capped at +0.2.
        volume_mb = estimated_volume_kb / 1024.0
        volume_modifier = min(0.2, volume_mb / 1000.0 * 0.05)
        return min(1.0, base + volume_modifier)
