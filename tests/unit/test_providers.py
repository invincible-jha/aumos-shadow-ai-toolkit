"""Unit tests for the AI provider domain registry.

Verifies that:
  - At least 50 domains are registered
  - All major provider groups are represented
  - resolve_provider() returns correct identifiers for exact matches
  - Wildcard pattern matching works correctly
  - Unknown domains return None
"""

from __future__ import annotations

import pytest

from aumos_shadow_ai_toolkit.core.providers import (
    AI_PROVIDER_DOMAINS,
    EXACT_AI_PROVIDER_DOMAINS,
    WILDCARD_AI_PROVIDER_DOMAINS,
    resolve_provider,
)


class TestProviderRegistrySize:
    """Verify the registry meets the minimum domain coverage requirement."""

    def test_at_least_50_domains_registered(self) -> None:
        """Registry must contain at least 50 domain entries."""
        assert len(AI_PROVIDER_DOMAINS) >= 50, (
            f"Expected >= 50 domains, found {len(AI_PROVIDER_DOMAINS)}"
        )

    def test_exact_domains_populated(self) -> None:
        """Exact-match domain dict must be non-empty."""
        assert len(EXACT_AI_PROVIDER_DOMAINS) > 0

    def test_wildcard_domains_populated(self) -> None:
        """Wildcard domain dict must be non-empty."""
        assert len(WILDCARD_AI_PROVIDER_DOMAINS) > 0


class TestProviderCoverage:
    """Verify all major provider groups are represented."""

    @pytest.mark.parametrize(
        "expected_provider",
        [
            "openai",
            "anthropic",
            "google",
            "azure-openai",
            "aws-bedrock",
            "cohere",
            "mistral",
            "huggingface",
            "replicate",
            "together",
            "perplexity",
            "groq",
            "deepseek",
            "xai",
            "stability",
            "elevenlabs",
        ],
    )
    def test_provider_represented(self, expected_provider: str) -> None:
        """Each major provider must have at least one registered domain."""
        registered_providers = set(AI_PROVIDER_DOMAINS.values())
        assert expected_provider in registered_providers, (
            f"Provider '{expected_provider}' has no registered domains"
        )


class TestResolveProviderExactMatch:
    """Test exact domain resolution."""

    def test_openai_api_resolved(self) -> None:
        """api.openai.com resolves to openai."""
        assert resolve_provider("api.openai.com") == "openai"

    def test_anthropic_resolved(self) -> None:
        """api.anthropic.com resolves to anthropic."""
        assert resolve_provider("api.anthropic.com") == "anthropic"

    def test_google_generative_language_resolved(self) -> None:
        """generativelanguage.googleapis.com resolves to google."""
        assert resolve_provider("generativelanguage.googleapis.com") == "google"

    def test_cohere_api_resolved(self) -> None:
        """api.cohere.com resolves to cohere."""
        assert resolve_provider("api.cohere.com") == "cohere"

    def test_mistral_resolved(self) -> None:
        """api.mistral.ai resolves to mistral."""
        assert resolve_provider("api.mistral.ai") == "mistral"

    def test_groq_resolved(self) -> None:
        """api.groq.com resolves to groq."""
        assert resolve_provider("api.groq.com") == "groq"

    def test_deepseek_resolved(self) -> None:
        """api.deepseek.com resolves to deepseek."""
        assert resolve_provider("api.deepseek.com") == "deepseek"

    def test_perplexity_resolved(self) -> None:
        """api.perplexity.ai resolves to perplexity."""
        assert resolve_provider("api.perplexity.ai") == "perplexity"

    def test_together_resolved(self) -> None:
        """api.together.xyz resolves to together."""
        assert resolve_provider("api.together.xyz") == "together"

    def test_huggingface_inference_resolved(self) -> None:
        """api-inference.huggingface.co resolves to huggingface."""
        assert resolve_provider("api-inference.huggingface.co") == "huggingface"

    def test_replicate_resolved(self) -> None:
        """api.replicate.com resolves to replicate."""
        assert resolve_provider("api.replicate.com") == "replicate"

    def test_xai_resolved(self) -> None:
        """api.x.ai resolves to xai."""
        assert resolve_provider("api.x.ai") == "xai"

    def test_stability_resolved(self) -> None:
        """api.stability.ai resolves to stability."""
        assert resolve_provider("api.stability.ai") == "stability"

    def test_elevenlabs_resolved(self) -> None:
        """api.elevenlabs.io resolves to elevenlabs."""
        assert resolve_provider("api.elevenlabs.io") == "elevenlabs"


class TestResolveProviderWildcardMatch:
    """Test wildcard suffix pattern matching."""

    def test_azure_openai_wildcard_matched(self) -> None:
        """Tenant-specific Azure OpenAI subdomain matches *.openai.azure.com pattern."""
        result = resolve_provider("my-company.openai.azure.com")
        assert result == "azure-openai"

    def test_azure_openai_another_tenant(self) -> None:
        """Another tenant-specific Azure OpenAI subdomain is matched."""
        result = resolve_provider("acme-corp-east.openai.azure.com")
        assert result == "azure-openai"

    def test_exact_wildcard_base_not_matched(self) -> None:
        """The base domain "openai.azure.com" without prefix should not match the wildcard."""
        # "*.openai.azure.com" requires at least one subdomain segment
        result = resolve_provider("openai.azure.com")
        assert result is None  # no exact match for base, wildcard needs prefix

    def test_aws_bedrock_us_east_resolved(self) -> None:
        """Known bedrock endpoint resolves to aws-bedrock."""
        assert resolve_provider("bedrock-runtime.us-east-1.amazonaws.com") == "aws-bedrock"


class TestResolveProviderNoMatch:
    """Test that unknown domains return None."""

    def test_unknown_domain_returns_none(self) -> None:
        """An unregistered domain returns None."""
        assert resolve_provider("api.unknownservice.example.com") is None

    def test_google_non_ai_domain_returns_none(self) -> None:
        """google.com itself is not an AI API domain."""
        assert resolve_provider("google.com") is None

    def test_empty_string_returns_none(self) -> None:
        """Empty string returns None gracefully."""
        assert resolve_provider("") is None

    def test_partial_match_not_returned(self) -> None:
        """Substring of a known domain does not match."""
        assert resolve_provider("openai.com") is None

    def test_internal_domain_not_matched(self) -> None:
        """Internal corporate domain is not classified as AI provider."""
        assert resolve_provider("internal-tools.company.internal") is None
