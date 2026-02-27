"""Unit tests for ShadowAIDetectionService.

Covers:
  - classify_data_sensitivity — path and size heuristics
  - compute_risk_score — weighted scoring formula
  - analyze_dns_queries — provider matching, deduplication
  - detect_from_network_log — full pipeline, aggregation, business value inference
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

import pytest

from aumos_shadow_ai_toolkit.api.schemas_shadow import DNSQuery, NetworkLogEntry
from aumos_shadow_ai_toolkit.core.services.detection_service import (
    ShadowAIDetectionService,
    _HIGH_SENSITIVITY_BYTES,
    _MEDIUM_SENSITIVITY_BYTES,
)

_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_NOW = datetime.now(tz=timezone.utc)


@pytest.fixture
def service() -> ShadowAIDetectionService:
    """ShadowAIDetectionService instance for tests."""
    return ShadowAIDetectionService(tenant_id=_TENANT_ID)


def _make_dns_query(
    domain: str,
    source_ip: str = "10.0.0.1",
    has_auth: bool = False,
) -> DNSQuery:
    return DNSQuery(
        queried_domain=domain,
        source_ip=source_ip,
        queried_at=_NOW,
        has_auth_header=has_auth,
    )


def _make_log_entry(
    domain: str,
    url_path: str = "",
    request_size_bytes: int = 0,
    has_auth: bool = False,
    source_ip: str = "10.0.0.1",
) -> NetworkLogEntry:
    return NetworkLogEntry(
        source_ip=source_ip,
        destination_domain=domain,
        url_path=url_path if url_path else None,
        request_size_bytes=request_size_bytes,
        has_auth_header=has_auth,
        observed_at=_NOW,
    )


# ---------------------------------------------------------------------------
# classify_data_sensitivity tests
# ---------------------------------------------------------------------------


class TestClassifyDataSensitivity:
    """Tests for sensitivity classification heuristics."""

    @pytest.mark.asyncio
    async def test_fine_tuning_path_is_critical(self, service: ShadowAIDetectionService) -> None:
        """Fine-tuning endpoints are always classified as critical."""
        result = await service.classify_data_sensitivity(
            domain="api.openai.com",
            url_path="/v1/fine-tunes",
            request_size_bytes=0,
        )
        assert result == "critical"

    @pytest.mark.asyncio
    async def test_very_large_payload_is_critical(self, service: ShadowAIDetectionService) -> None:
        """Payloads above 128 KB are classified critical regardless of path."""
        result = await service.classify_data_sensitivity(
            domain="api.openai.com",
            url_path="/v1/chat/completions",
            request_size_bytes=131_073,
        )
        assert result == "critical"

    @pytest.mark.asyncio
    async def test_large_payload_known_path_is_high(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Payloads above 32 KB are high sensitivity."""
        result = await service.classify_data_sensitivity(
            domain="api.anthropic.com",
            url_path="/v1/messages",
            request_size_bytes=_HIGH_SENSITIVITY_BYTES + 1,
        )
        assert result == "high"

    @pytest.mark.asyncio
    async def test_known_path_small_payload_is_medium(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Known inference path with small payload is medium sensitivity."""
        result = await service.classify_data_sensitivity(
            domain="api.openai.com",
            url_path="/v1/chat/completions",
            request_size_bytes=100,
        )
        assert result == "medium"

    @pytest.mark.asyncio
    async def test_medium_payload_no_path_is_medium(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Payload above 4 KB with no path is medium."""
        result = await service.classify_data_sensitivity(
            domain="api.groq.com",
            url_path="",
            request_size_bytes=_MEDIUM_SENSITIVITY_BYTES + 1,
        )
        assert result == "medium"

    @pytest.mark.asyncio
    async def test_tiny_payload_no_path_is_low(self, service: ShadowAIDetectionService) -> None:
        """Tiny payload with no known path is low sensitivity."""
        result = await service.classify_data_sensitivity(
            domain="api.openai.com",
            url_path="",
            request_size_bytes=256,
        )
        assert result == "low"

    @pytest.mark.asyncio
    async def test_training_path_is_critical(self, service: ShadowAIDetectionService) -> None:
        """Training path variants are always critical."""
        result = await service.classify_data_sensitivity(
            domain="api.cohere.com",
            url_path="/training/jobs",
            request_size_bytes=0,
        )
        assert result == "critical"


# ---------------------------------------------------------------------------
# compute_risk_score tests
# ---------------------------------------------------------------------------


class TestComputeRiskScore:
    """Tests for the weighted risk score formula."""

    @pytest.mark.asyncio
    async def test_critical_sensitivity_with_auth_is_high_risk(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Critical sensitivity + auth header produces a high risk score."""
        score = await service.compute_risk_score(
            sensitivity="critical",
            provider="openai",
            has_auth=True,
        )
        assert score >= 70.0

    @pytest.mark.asyncio
    async def test_low_sensitivity_no_auth_azure_is_low_risk(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Low sensitivity + no auth + governed provider (Azure) is lower risk."""
        score = await service.compute_risk_score(
            sensitivity="low",
            provider="azure-openai",
            has_auth=False,
        )
        # Azure-openai has lower provider risk (0.3) and sensitivity is low
        assert score < 40.0

    @pytest.mark.asyncio
    async def test_score_within_valid_range(self, service: ShadowAIDetectionService) -> None:
        """Risk score is always within 0.0–100.0."""
        for sensitivity in ("low", "medium", "high", "critical"):
            for has_auth in (True, False):
                score = await service.compute_risk_score(
                    sensitivity=sensitivity,
                    provider="deepseek",
                    has_auth=has_auth,
                )
                assert 0.0 <= score <= 100.0, (
                    f"Score {score} out of range for {sensitivity}/{has_auth}"
                )

    @pytest.mark.asyncio
    async def test_auth_increases_score(self, service: ShadowAIDetectionService) -> None:
        """Having an auth header increases risk score vs no auth."""
        score_with_auth = await service.compute_risk_score(
            sensitivity="medium",
            provider="openai",
            has_auth=True,
        )
        score_no_auth = await service.compute_risk_score(
            sensitivity="medium",
            provider="openai",
            has_auth=False,
        )
        assert score_with_auth > score_no_auth

    @pytest.mark.asyncio
    async def test_high_risk_provider_raises_score(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Higher provider risk weight produces higher overall score."""
        score_high_risk = await service.compute_risk_score(
            sensitivity="medium",
            provider="deepseek",  # weight 0.9
            has_auth=False,
        )
        score_low_risk = await service.compute_risk_score(
            sensitivity="medium",
            provider="azure-openai",  # weight 0.3
            has_auth=False,
        )
        assert score_high_risk > score_low_risk


# ---------------------------------------------------------------------------
# analyze_dns_queries tests
# ---------------------------------------------------------------------------


class TestAnalyzeDNSQueries:
    """Tests for DNS query analysis."""

    @pytest.mark.asyncio
    async def test_known_domain_produces_detection(
        self, service: ShadowAIDetectionService
    ) -> None:
        """DNS query to known AI provider domain produces a detection."""
        queries = [_make_dns_query("api.openai.com")]
        detections = await service.analyze_dns_queries(queries)
        assert len(detections) == 1
        assert detections[0].provider == "openai"
        assert detections[0].tenant_id == _TENANT_ID

    @pytest.mark.asyncio
    async def test_unknown_domain_produces_no_detection(
        self, service: ShadowAIDetectionService
    ) -> None:
        """DNS query to unknown domain produces no detections."""
        queries = [_make_dns_query("internal.company.com")]
        detections = await service.analyze_dns_queries(queries)
        assert len(detections) == 0

    @pytest.mark.asyncio
    async def test_duplicate_domains_deduplicated(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Multiple queries to same domain produce only one detection."""
        queries = [
            _make_dns_query("api.anthropic.com"),
            _make_dns_query("api.anthropic.com"),
            _make_dns_query("api.anthropic.com"),
        ]
        detections = await service.analyze_dns_queries(queries)
        assert len(detections) == 1

    @pytest.mark.asyncio
    async def test_multiple_providers_produce_separate_detections(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Different provider domains produce separate detection records."""
        queries = [
            _make_dns_query("api.openai.com"),
            _make_dns_query("api.anthropic.com"),
            _make_dns_query("api.groq.com"),
        ]
        detections = await service.analyze_dns_queries(queries)
        assert len(detections) == 3
        providers = {d.provider for d in detections}
        assert providers == {"openai", "anthropic", "groq"}

    @pytest.mark.asyncio
    async def test_detection_has_correct_tenant_id(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Produced detections carry the correct tenant_id."""
        queries = [_make_dns_query("api.mistral.ai")]
        detections = await service.analyze_dns_queries(queries)
        assert all(d.tenant_id == _TENANT_ID for d in detections)

    @pytest.mark.asyncio
    async def test_detection_status_is_detected(
        self, service: ShadowAIDetectionService
    ) -> None:
        """New detections have status='detected'."""
        queries = [_make_dns_query("api.groq.com")]
        detections = await service.analyze_dns_queries(queries)
        assert all(d.status == "detected" for d in detections)


# ---------------------------------------------------------------------------
# detect_from_network_log tests
# ---------------------------------------------------------------------------


class TestDetectFromNetworkLog:
    """Tests for the full network log detection pipeline."""

    @pytest.mark.asyncio
    async def test_empty_log_produces_no_detections(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Empty log returns empty detection list."""
        detections = await service.detect_from_network_log([])
        assert detections == []

    @pytest.mark.asyncio
    async def test_non_ai_traffic_not_detected(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Network log entries to non-AI domains produce no detections."""
        entries = [
            _make_log_entry("github.com", "/api/v3/repos"),
            _make_log_entry("s3.amazonaws.com", "/bucket/file.txt"),
        ]
        detections = await service.detect_from_network_log(entries)
        assert len(detections) == 0

    @pytest.mark.asyncio
    async def test_ai_traffic_detected(self, service: ShadowAIDetectionService) -> None:
        """Network log entries to AI provider domain produce a detection."""
        entries = [
            _make_log_entry(
                "api.openai.com",
                url_path="/v1/chat/completions",
                request_size_bytes=2048,
                has_auth=True,
            )
        ]
        detections = await service.detect_from_network_log(entries)
        assert len(detections) == 1
        assert detections[0].provider == "openai"

    @pytest.mark.asyncio
    async def test_business_value_inferred_from_path(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Business value indicator is inferred from URL path."""
        entries = [
            _make_log_entry(
                "api.openai.com",
                url_path="/v1/chat/completions",
                request_size_bytes=512,
            )
        ]
        detections = await service.detect_from_network_log(entries)
        assert detections[0].business_value_indicator == "text-generation"

    @pytest.mark.asyncio
    async def test_multiple_entries_same_domain_aggregated(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Multiple entries to the same domain are aggregated into one detection."""
        entries = [
            _make_log_entry("api.anthropic.com", request_size_bytes=1000),
            _make_log_entry("api.anthropic.com", request_size_bytes=2000),
            _make_log_entry("api.anthropic.com", request_size_bytes=3000),
        ]
        detections = await service.detect_from_network_log(entries)
        assert len(detections) == 1
        assert detections[0].provider == "anthropic"

    @pytest.mark.asyncio
    async def test_daily_cost_estimated_from_volume(
        self, service: ShadowAIDetectionService
    ) -> None:
        """Estimated daily cost is computed from total request byte volume."""
        entries = [
            _make_log_entry("api.cohere.com", request_size_bytes=8192),  # 2 * 4KB
        ]
        detections = await service.detect_from_network_log(entries)
        assert detections[0].estimated_daily_cost_usd > Decimal("0")

    @pytest.mark.asyncio
    async def test_detection_has_unique_id(self, service: ShadowAIDetectionService) -> None:
        """Each detection gets a unique UUID."""
        entries = [
            _make_log_entry("api.openai.com"),
            _make_log_entry("api.anthropic.com"),
        ]
        detections = await service.detect_from_network_log(entries)
        ids = [d.id for d in detections]
        assert len(ids) == len(set(ids))
