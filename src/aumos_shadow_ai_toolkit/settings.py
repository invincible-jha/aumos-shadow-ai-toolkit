"""Shadow AI Toolkit service settings extending AumOS base configuration."""

import json
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

from aumos_common.config import AumOSSettings


class Settings(AumOSSettings):
    """Configuration for the AumOS Shadow AI Toolkit service.

    Extends base AumOS settings with shadow-ai-specific configuration
    for network scanning, risk thresholds, and migration workflows.

    All settings use the AUMOS_SHADOW_AI_ environment variable prefix.
    """

    service_name: str = "aumos-shadow-ai-toolkit"

    # ---------------------------------------------------------------------------
    # Network scanner
    # ---------------------------------------------------------------------------
    scan_interval_seconds: int = Field(
        default=3600,
        description="Interval in seconds between automated network scans",
    )
    scan_timeout_seconds: int = Field(
        default=300,
        description="Maximum time in seconds a single scan may run",
    )
    max_concurrent_scans: int = Field(
        default=5,
        description="Maximum number of concurrent network scans per tenant",
    )
    known_ai_endpoints_json: str = Field(
        default='["api.openai.com","api.anthropic.com","api.perplexity.ai","generativelanguage.googleapis.com","api.cohere.com","api.mistral.ai","api.together.xyz","api.replicate.com","api.huggingface.co","api.groq.com"]',
        alias="AUMOS_SHADOW_AI_KNOWN_AI_ENDPOINTS",
        description="JSON array of known AI API domain patterns to detect",
    )

    # ---------------------------------------------------------------------------
    # Risk thresholds
    # ---------------------------------------------------------------------------
    risk_threshold_critical: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Risk score at or above which a discovery is rated critical (0–1)",
    )
    risk_threshold_high: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Risk score at or above which a discovery is rated high (0–1)",
    )
    risk_threshold_medium: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Risk score at or above which a discovery is rated medium (0–1)",
    )

    # ---------------------------------------------------------------------------
    # Migration settings
    # ---------------------------------------------------------------------------
    migration_expiry_days: int = Field(
        default=90,
        description="Days after creation before an inactive migration plan expires",
    )
    migration_sla_critical_days: int = Field(
        default=7,
        description="Days to complete migration for critical-risk discoveries",
    )
    migration_sla_high_days: int = Field(
        default=30,
        description="Days to complete migration for high-risk discoveries",
    )

    # ---------------------------------------------------------------------------
    # Upstream service URLs
    # ---------------------------------------------------------------------------
    governance_engine_url: str = Field(
        default="http://localhost:8016",
        description="Base URL for aumos-governance-engine policy evaluation",
    )
    model_registry_url: str = Field(
        default="http://localhost:8003",
        description="Base URL for aumos-model-registry governed alternatives lookup",
    )

    # ---------------------------------------------------------------------------
    # HTTP client
    # ---------------------------------------------------------------------------
    http_timeout: float = Field(
        default=30.0,
        description="Timeout in seconds for HTTP calls to downstream services",
    )
    http_max_retries: int = Field(
        default=3,
        description="Maximum retry attempts for HTTP calls to upstream services",
    )

    @field_validator("known_ai_endpoints_json", mode="before")
    @classmethod
    def validate_known_ai_endpoints(cls, value: Any) -> str:
        """Ensure known_ai_endpoints_json is valid JSON string.

        Args:
            value: Raw value from environment.

        Returns:
            Validated JSON string.

        Raises:
            ValueError: If value is not valid JSON or not a list.
        """
        if isinstance(value, list):
            return json.dumps(value)
        if isinstance(value, str):
            parsed = json.loads(value)
            if not isinstance(parsed, list):
                raise ValueError("AUMOS_SHADOW_AI_KNOWN_AI_ENDPOINTS must be a JSON array")
            return value
        raise ValueError("AUMOS_SHADOW_AI_KNOWN_AI_ENDPOINTS must be a JSON array string")

    @property
    def known_ai_endpoints(self) -> list[str]:
        """Parsed list of known AI API endpoint domains.

        Returns:
            List of domain strings to match against in network scans.
        """
        result: list[str] = json.loads(self.known_ai_endpoints_json)
        return result

    model_config = SettingsConfigDict(env_prefix="AUMOS_SHADOW_AI_")
