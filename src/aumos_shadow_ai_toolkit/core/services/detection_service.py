"""Shadow AI Detection Service — network traffic analysis engine.

Analyses DNS query logs and network metadata to identify employees
communicating with unauthorized AI provider APIs. Only metadata is
processed — request/response content is never inspected or stored.

Detection methods supported:
  1. DNS query analysis  — match queries against known AI provider domains
  2. HTTP metadata analysis — detect Bearer token patterns to AI endpoints
  3. Traffic volume analysis — identify sustained connections to AI APIs

Risk scoring formula:
  risk_score = data_sensitivity_weight * 0.4 + compliance_risk * 0.4 + provider_risk * 0.2
  Final score is normalized to 0.00–100.00.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.api.schemas_shadow import DNSQuery, NetworkLogEntry
from aumos_shadow_ai_toolkit.core.models.shadow_detection import ShadowAIDetection
from aumos_shadow_ai_toolkit.core.providers import resolve_provider

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Sensitivity classification constants
# ---------------------------------------------------------------------------

# URL path fragments that hint at higher data sensitivity
_HIGH_SENSITIVITY_PATH_FRAGMENTS: frozenset[str] = frozenset(
    {
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/messages",
        "/generate",
        "/invoke",
        "/fine-tunes",
        "/fine_tuning",
        "/assistants",
        "/threads",
        "/runs",
    }
)

# Request size thresholds (bytes) for escalating sensitivity
_MEDIUM_SENSITIVITY_BYTES: int = 4_096    # 4 KB
_HIGH_SENSITIVITY_BYTES: int = 32_768     # 32 KB
_CRITICAL_SENSITIVITY_BYTES: int = 131_072  # 128 KB

# ---------------------------------------------------------------------------
# Provider risk weights (used in risk score computation)
# ---------------------------------------------------------------------------

# Higher risk = provider has fewer data processing agreements in typical enterprises
_PROVIDER_RISK_WEIGHTS: dict[str, float] = {
    "openai": 0.6,
    "anthropic": 0.5,
    "google": 0.5,
    "azure-openai": 0.3,   # Often covered by enterprise agreements
    "aws-bedrock": 0.3,
    "cohere": 0.6,
    "mistral": 0.7,
    "huggingface": 0.7,
    "replicate": 0.8,
    "together": 0.8,
    "perplexity": 0.8,
    "groq": 0.7,
    "deepseek": 0.9,       # Non-EU/US jurisdiction flag
    "xai": 0.7,
    "stability": 0.6,
    "elevenlabs": 0.6,
    "midjourney": 0.7,
    "runway": 0.7,
    "character-ai": 0.9,
    "openrouter": 0.8,
    "fireworks": 0.7,
    "anyscale": 0.6,
    "lepton": 0.8,
    "aleph-alpha": 0.4,    # EU-based, typically better coverage
    "ai21": 0.7,
    "inflection": 0.8,
    "novita": 0.9,
    "cerebras": 0.6,
    "scale": 0.5,
    "writer": 0.6,
    "jasper": 0.7,
    "copy-ai": 0.7,
}

_DEFAULT_PROVIDER_RISK: float = 0.8

# ---------------------------------------------------------------------------
# Sensitivity data weights
# ---------------------------------------------------------------------------

_SENSITIVITY_WEIGHTS: dict[str, float] = {
    "low": 0.1,
    "medium": 0.4,
    "high": 0.75,
    "critical": 1.0,
}

# ---------------------------------------------------------------------------
# Business value inference
# ---------------------------------------------------------------------------

_PATH_TO_BUSINESS_VALUE: dict[str, str] = {
    "/v1/chat/completions": "text-generation",
    "/v1/completions": "text-generation",
    "/v1/embeddings": "data-analysis",
    "/messages": "text-generation",
    "/generate": "text-generation",
    "/invoke": "text-generation",
    "/fine-tunes": "code-assist",
    "/fine_tuning": "code-assist",
    "/images/generations": "image-generation",
    "/image": "image-generation",
    "/assistants": "productivity",
    "/threads": "productivity",
    "/runs": "productivity",
    "/audio": "productivity",
    "/transcriptions": "productivity",
}


class ShadowAIDetectionService:
    """Analyses network traffic data to detect unauthorized AI API usage.

    Detection methods:
    1. DNS query analysis — match against known AI provider domains
    2. HTTP metadata analysis — detect Bearer token patterns to AI endpoints
    3. Traffic volume analysis — identify sustained connections to AI APIs

    Risk scoring formula:
        risk_score = sensitivity_weight * 0.4 + compliance_risk * 0.4 + provider_risk * 0.2
    All weights are normalized to produce a final score on the 0.00–100.00 scale.
    """

    def __init__(self, tenant_id: uuid.UUID) -> None:
        """Initialise for a specific tenant context.

        Args:
            tenant_id: UUID of the tenant whose traffic is being analysed.
        """
        self._tenant_id = tenant_id

    async def analyze_dns_queries(self, queries: list[DNSQuery]) -> list[ShadowAIDetection]:
        """Match DNS queries against known AI provider domains.

        Creates ShadowAIDetection instances (not persisted here) for each
        query that resolves to a known AI provider. Duplicate domains within
        the same batch produce a single detection with aggregated metadata.

        Args:
            queries: List of DNS query metadata records.

        Returns:
            List of ShadowAIDetection instances (unsaved) for matched providers.
        """
        detections: list[ShadowAIDetection] = []
        seen_domains: set[str] = set()

        for query in queries:
            domain = query.queried_domain.lower().strip()
            provider = resolve_provider(domain)

            if provider is None:
                continue

            if domain in seen_domains:
                continue
            seen_domains.add(domain)

            sensitivity = await self.classify_data_sensitivity(
                domain=domain,
                url_path="",
                request_size_bytes=0,
            )
            risk_score = await self.compute_risk_score(
                sensitivity=sensitivity,
                provider=provider,
                has_auth=query.has_auth_header,
            )

            detection = ShadowAIDetection.__new__(ShadowAIDetection)
            detection.id = uuid.uuid4()
            detection.tenant_id = self._tenant_id
            detection.source_ip = query.source_ip
            detection.destination_domain = domain
            detection.provider = provider
            detection.estimated_data_sensitivity = sensitivity
            detection.estimated_daily_cost_usd = Decimal("0.0000")
            detection.compliance_risk_score = Decimal(str(round(risk_score, 2)))
            detection.business_value_indicator = "unknown"
            detection.status = "detected"
            detection.created_at = datetime.now(tz=timezone.utc)
            detection.updated_at = datetime.now(tz=timezone.utc)

            detections.append(detection)

            logger.info(
                "DNS-based shadow AI detection",
                tenant_id=str(self._tenant_id),
                domain=domain,
                provider=provider,
                sensitivity=sensitivity,
                risk_score=risk_score,
            )

        return detections

    async def classify_data_sensitivity(
        self,
        domain: str,
        url_path: str,
        request_size_bytes: int,
    ) -> str:
        """Classify data sensitivity based on URL path patterns and request size.

        Sensitivity classification heuristic:
        - "critical": Very large payloads (>128 KB) or paths indicating fine-tuning
        - "high": Moderate-large payloads (>32 KB) or known high-sensitivity endpoints
        - "medium": Small payloads (>4 KB) or any recognized AI inference endpoint
        - "low": Minimal traffic, health/status checks, or unrecognized paths

        Args:
            domain: Target AI API domain.
            url_path: URL path of the request (empty string if unavailable).
            request_size_bytes: Size of the request payload in bytes.

        Returns:
            Sensitivity category: "low" | "medium" | "high" | "critical".
        """
        path_lower = url_path.lower()

        # Fine-tuning or training endpoints are always critical
        if any(frag in path_lower for frag in {"/fine-tunes", "/fine_tuning", "/training"}):
            return "critical"

        if request_size_bytes >= _CRITICAL_SENSITIVITY_BYTES:
            return "critical"

        if request_size_bytes >= _HIGH_SENSITIVITY_BYTES:
            return "high"

        # Any recognised high-sensitivity path
        if any(frag in path_lower for frag in _HIGH_SENSITIVITY_PATH_FRAGMENTS):
            if request_size_bytes >= _MEDIUM_SENSITIVITY_BYTES:
                return "high"
            return "medium"

        if request_size_bytes >= _MEDIUM_SENSITIVITY_BYTES:
            return "medium"

        # Minimal traffic — health check or unknown endpoint
        return "low"

    async def compute_risk_score(
        self,
        sensitivity: str,
        provider: str,
        has_auth: bool,
    ) -> float:
        """Compute a weighted risk score on the 0.00–100.00 scale.

        Formula:
          risk_score = (sensitivity_weight * 0.4 + compliance_risk * 0.4 + provider_risk * 0.2) * 100

        Where:
          sensitivity_weight — from _SENSITIVITY_WEIGHTS lookup
          compliance_risk    — elevated if auth header present (confirms active API usage)
          provider_risk      — from _PROVIDER_RISK_WEIGHTS (jurisdiction/DPA coverage)

        Args:
            sensitivity: Data sensitivity category string.
            provider: Canonical provider identifier.
            has_auth: Whether the request includes an Authorization/API-key header.

        Returns:
            Risk score between 0.0 and 100.0 (two decimal precision).
        """
        sensitivity_weight = _SENSITIVITY_WEIGHTS.get(sensitivity, 0.1)

        # Active API usage (auth header present) raises compliance risk
        compliance_risk = 0.6 if has_auth else 0.3
        if sensitivity in {"high", "critical"}:
            compliance_risk = min(compliance_risk + 0.2, 1.0)

        provider_risk = _PROVIDER_RISK_WEIGHTS.get(provider, _DEFAULT_PROVIDER_RISK)

        raw_score = (
            sensitivity_weight * 0.4
            + compliance_risk * 0.4
            + provider_risk * 0.2
        )
        return round(min(raw_score * 100.0, 100.0), 2)

    async def detect_from_network_log(
        self, log_entries: list[NetworkLogEntry]
    ) -> list[ShadowAIDetection]:
        """Main detection pipeline: parse logs, match providers, score risk, create detections.

        Processes a batch of raw network log entries through the full detection
        pipeline. Each entry is matched against the AI provider registry, classified
        for data sensitivity, scored for risk, and returned as a ShadowAIDetection
        instance ready for persistence.

        No content is stored — only connection metadata (destination, size, timing).

        Args:
            log_entries: List of raw network log entry records.

        Returns:
            List of ShadowAIDetection instances (unsaved) for all matched AI traffic.
        """
        detections: list[ShadowAIDetection] = []
        domain_aggregates: dict[str, dict[str, Any]] = {}

        for entry in log_entries:
            domain = entry.destination_domain.lower().strip()
            provider = resolve_provider(domain)

            if provider is None:
                continue

            # Aggregate multiple log entries for the same domain
            if domain not in domain_aggregates:
                domain_aggregates[domain] = {
                    "provider": provider,
                    "source_ip": entry.source_ip,
                    "url_path": entry.url_path or "",
                    "total_bytes": entry.request_size_bytes,
                    "has_auth": entry.has_auth_header,
                    "entry_count": 1,
                    "url_paths": {entry.url_path or ""},
                }
            else:
                agg = domain_aggregates[domain]
                agg["total_bytes"] = agg["total_bytes"] + entry.request_size_bytes
                agg["has_auth"] = agg["has_auth"] or entry.has_auth_header
                agg["entry_count"] = agg["entry_count"] + 1
                if entry.url_path:
                    agg["url_paths"].add(entry.url_path)

        for domain, agg in domain_aggregates.items():
            provider = agg["provider"]

            # Use the most informative URL path seen for classification
            representative_path = max(
                agg["url_paths"],
                key=lambda p: len(p),
                default="",
            )

            sensitivity = await self.classify_data_sensitivity(
                domain=domain,
                url_path=representative_path,
                request_size_bytes=agg["total_bytes"],
            )
            risk_score = await self.compute_risk_score(
                sensitivity=sensitivity,
                provider=provider,
                has_auth=agg["has_auth"],
            )

            business_value = _PATH_TO_BUSINESS_VALUE.get(
                representative_path.lower(), "unknown"
            )

            # Estimate daily cost: rough proxy from byte volume
            # $0.01 per 4 KB of API traffic is a conservative upper bound
            estimated_daily_cost = Decimal(
                str(round((agg["total_bytes"] / 4096) * 0.01, 4))
            )

            detection = ShadowAIDetection.__new__(ShadowAIDetection)
            detection.id = uuid.uuid4()
            detection.tenant_id = self._tenant_id
            detection.source_ip = agg["source_ip"]
            detection.destination_domain = domain
            detection.provider = provider
            detection.estimated_data_sensitivity = sensitivity
            detection.estimated_daily_cost_usd = estimated_daily_cost
            detection.compliance_risk_score = Decimal(str(round(risk_score, 2)))
            detection.business_value_indicator = business_value
            detection.status = "detected"
            detection.created_at = datetime.now(tz=timezone.utc)
            detection.updated_at = datetime.now(tz=timezone.utc)

            detections.append(detection)

            logger.info(
                "Network-log shadow AI detection",
                tenant_id=str(self._tenant_id),
                domain=domain,
                provider=provider,
                sensitivity=sensitivity,
                risk_score=risk_score,
                entry_count=agg["entry_count"],
                total_bytes=agg["total_bytes"],
            )

        return detections
