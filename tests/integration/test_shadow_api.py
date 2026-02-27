"""Integration tests for the Shadow AI Detection and Amnesty API routes.

Tests the full detection-to-proposal flow via FastAPI test client.
All database, Kafka, and external service dependencies are mocked via
monkeypatching of repository classes.

Run with: pytest tests/integration/test_shadow_api.py
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# We import a minimal FastAPI app rather than the full service entry point
# to avoid requiring aumos-common lifespan dependencies in tests.
# ---------------------------------------------------------------------------

from fastapi import FastAPI

from aumos_shadow_ai_toolkit.api.routes.shadow_ai import router


def _create_test_app() -> FastAPI:
    """Create a minimal FastAPI test app with only the shadow AI router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return app


@pytest.fixture
def test_app() -> FastAPI:
    """Minimal test application."""
    return _create_test_app()


@pytest.fixture
def client(test_app: FastAPI) -> TestClient:
    """FastAPI TestClient for the shadow AI routes."""
    return TestClient(test_app)


_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_DETECTION_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")
_NOW = datetime.now(tz=timezone.utc)


def _make_detection_dict() -> dict[str, Any]:
    """Build a minimal detection dict for mock returns."""
    return {
        "id": str(_DETECTION_ID),
        "tenant_id": str(_TENANT_ID),
        "source_ip": "10.0.0.1",
        "destination_domain": "api.openai.com",
        "provider": "openai",
        "estimated_data_sensitivity": "medium",
        "estimated_daily_cost_usd": "0.0100",
        "compliance_risk_score": "45.00",
        "business_value_indicator": "text-generation",
        "status": "detected",
        "created_at": _NOW.isoformat(),
        "updated_at": _NOW.isoformat(),
    }


# ---------------------------------------------------------------------------
# Detection listing tests
# ---------------------------------------------------------------------------


class TestListDetectionsEndpoint:
    """Tests for GET /api/v1/shadow-ai/detections."""

    def test_empty_detections_returns_200(self, client: TestClient) -> None:
        """Endpoint returns 200 with empty list when no detections exist."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.list_by_tenant = AsyncMock(return_value=([], 0))

            response = client.get(
                "/api/v1/shadow-ai/detections",
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_pagination_parameters_accepted(self, client: TestClient) -> None:
        """Pagination query parameters are passed to the repository."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.list_by_tenant = AsyncMock(return_value=([], 0))

            response = client.get(
                "/api/v1/shadow-ai/detections?page=2&page_size=10",
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200

    def test_severity_filter_accepted(self, client: TestClient) -> None:
        """severity query parameter is accepted without validation error."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.list_by_tenant = AsyncMock(return_value=([], 0))

            response = client.get(
                "/api/v1/shadow-ai/detections?severity=high",
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200

    def test_provider_filter_accepted(self, client: TestClient) -> None:
        """provider query parameter is accepted without validation error."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.list_by_tenant = AsyncMock(return_value=([], 0))

            response = client.get(
                "/api/v1/shadow-ai/detections?provider=openai",
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Amnesty program tests
# ---------------------------------------------------------------------------


class TestAmnestyProgramEndpoints:
    """Tests for amnesty program initiation and status endpoints."""

    def test_initiate_amnesty_requires_message(self, client: TestClient) -> None:
        """Missing or too-short message causes 422 validation error."""
        response = client.post(
            "/api/v1/shadow-ai/amnesty-program/initiate",
            headers={"X-Tenant-ID": str(_TENANT_ID)},
            json={"notification_message": "short", "grace_period_days": 30},
        )
        # "short" is 5 chars, minimum is 10
        assert response.status_code == 422

    def test_initiate_amnesty_grace_period_bounds(self, client: TestClient) -> None:
        """Grace period of 0 causes 422; valid values pass validation."""
        response = client.post(
            "/api/v1/shadow-ai/amnesty-program/initiate",
            headers={"X-Tenant-ID": str(_TENANT_ID)},
            json={
                "notification_message": "Valid notification message for the amnesty program.",
                "grace_period_days": 0,
            },
        )
        assert response.status_code == 422

    def test_get_amnesty_status_no_active_program(self, client: TestClient) -> None:
        """GET status returns 200 with status='none' when no program exists."""
        with (
            patch(
                "aumos_shadow_ai_toolkit.api.routes.shadow_ai.AmnestyProgramRepository"
            ) as MockAmnestyRepo,
            patch(
                "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
            ) as MockDetectionRepo,
        ):
            amnesty_instance = MockAmnestyRepo.return_value
            amnesty_instance.get_active_for_tenant = AsyncMock(return_value=None)

            detection_instance = MockDetectionRepo.return_value
            detection_instance.list_by_tenant = AsyncMock(return_value=([], 0))

            response = client.get(
                f"/api/v1/shadow-ai/amnesty-program/{_TENANT_ID}/status",
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "none"
        assert not data["is_active"]
        assert data["program_id"] is None


# ---------------------------------------------------------------------------
# Network log analysis tests
# ---------------------------------------------------------------------------


class TestAnalyzeNetworkLogsEndpoint:
    """Tests for POST /api/v1/shadow-ai/analyze."""

    def test_analyze_with_ai_traffic_returns_detections(self, client: TestClient) -> None:
        """Submitting AI provider traffic returns detection results."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.bulk_create = AsyncMock(return_value=[])

            payload = {
                "tenant_id": str(_TENANT_ID),
                "log_entries": [
                    {
                        "source_ip": "192.168.1.50",
                        "destination_domain": "api.openai.com",
                        "url_path": "/v1/chat/completions",
                        "request_size_bytes": 2048,
                        "has_auth_header": True,
                        "observed_at": _NOW.isoformat(),
                    }
                ],
            }

            response = client.post(
                "/api/v1/shadow-ai/analyze",
                json=payload,
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["detections_found"] >= 1
        assert "openai" in data["providers_detected"]

    def test_analyze_with_non_ai_traffic_returns_zero_detections(
        self, client: TestClient
    ) -> None:
        """Non-AI traffic produces zero detections."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.bulk_create = AsyncMock(return_value=[])

            payload = {
                "tenant_id": str(_TENANT_ID),
                "log_entries": [
                    {
                        "source_ip": "192.168.1.50",
                        "destination_domain": "github.com",
                        "url_path": "/api/v3/repos",
                        "request_size_bytes": 512,
                        "has_auth_header": False,
                        "observed_at": _NOW.isoformat(),
                    }
                ],
            }

            response = client.post(
                "/api/v1/shadow-ai/analyze",
                json=payload,
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["detections_found"] == 0
        assert data["providers_detected"] == []

    def test_analyze_empty_log_entries_rejected(self, client: TestClient) -> None:
        """Submitting empty log_entries fails validation."""
        payload = {
            "tenant_id": str(_TENANT_ID),
            "log_entries": [],
        }
        response = client.post(
            "/api/v1/shadow-ai/analyze",
            json=payload,
            headers={"X-Tenant-ID": str(_TENANT_ID)},
        )
        assert response.status_code == 422

    def test_analyze_multiple_providers_detected(self, client: TestClient) -> None:
        """Multiple AI provider domains in one submission produce multiple detections."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.bulk_create = AsyncMock(return_value=[])

            payload = {
                "tenant_id": str(_TENANT_ID),
                "log_entries": [
                    {
                        "source_ip": "192.168.1.50",
                        "destination_domain": "api.openai.com",
                        "url_path": "/v1/chat/completions",
                        "request_size_bytes": 1024,
                        "has_auth_header": True,
                        "observed_at": _NOW.isoformat(),
                    },
                    {
                        "source_ip": "192.168.1.51",
                        "destination_domain": "api.anthropic.com",
                        "url_path": "/v1/messages",
                        "request_size_bytes": 2048,
                        "has_auth_header": True,
                        "observed_at": _NOW.isoformat(),
                    },
                    {
                        "source_ip": "192.168.1.52",
                        "destination_domain": "api.groq.com",
                        "url_path": "/openai/v1/chat/completions",
                        "request_size_bytes": 512,
                        "has_auth_header": True,
                        "observed_at": _NOW.isoformat(),
                    },
                ],
            }

            response = client.post(
                "/api/v1/shadow-ai/analyze",
                json=payload,
                headers={"X-Tenant-ID": str(_TENANT_ID)},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["detections_found"] == 3
        providers = set(data["providers_detected"])
        assert "openai" in providers
        assert "anthropic" in providers
        assert "groq" in providers

    def test_analyze_risk_score_included_in_response(self, client: TestClient) -> None:
        """Analysis response includes highest risk score."""
        with patch(
            "aumos_shadow_ai_toolkit.api.routes.shadow_ai.ShadowDetectionRepository"
        ) as MockRepo:
            instance = MockRepo.return_value
            instance.bulk_create = AsyncMock(return_value=[])

            payload = {
                "tenant_id": str(_TENANT_ID),
                "log_entries": [
                    {
                        "source_ip": "10.0.0.1",
                        "destination_domain": "api.deepseek.com",
                        "url_path": "/v1/chat/completions",
                        "request_size_bytes": 50000,
                        "has_auth_header": True,
                        "observed_at": _NOW.isoformat(),
                    }
                ],
            }

            response = client.post("/api/v1/shadow-ai/analyze", json=payload)

        assert response.status_code == 200
        data = response.json()
        assert float(data["highest_risk_score"]) > 0
