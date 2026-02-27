"""AI provider domain registry for shadow AI detection.

Maps known AI API domains to their canonical provider identifiers.
Used by the detection engine to classify network traffic as shadow AI usage.

Wildcard patterns (e.g., "*.openai.azure.com") are supported via prefix/suffix
matching in the detection service.
"""

# Mapping of API domain patterns to provider identifiers.
# Wildcard entries use "*" prefix notation and require pattern matching logic
# in the consumer (ShadowAIDetectionService.analyze_dns_queries).
AI_PROVIDER_DOMAINS: dict[str, str] = {
    # ---------------------------------------------------------------------------
    # OpenAI
    # ---------------------------------------------------------------------------
    "api.openai.com": "openai",
    "chat.openai.com": "openai",
    "platform.openai.com": "openai",
    "oaidalleapiprodscus.blob.core.windows.net": "openai",
    "openaiapi-prod.azure-api.net": "openai",
    # ---------------------------------------------------------------------------
    # Anthropic
    # ---------------------------------------------------------------------------
    "api.anthropic.com": "anthropic",
    "claude.ai": "anthropic",
    # ---------------------------------------------------------------------------
    # Google AI / Vertex AI
    # ---------------------------------------------------------------------------
    "generativelanguage.googleapis.com": "google",
    "aiplatform.googleapis.com": "google",
    "us-central1-aiplatform.googleapis.com": "google",
    "europe-west1-aiplatform.googleapis.com": "google",
    "asia-east1-aiplatform.googleapis.com": "google",
    "bard.google.com": "google",
    "makersuite.google.com": "google",
    # ---------------------------------------------------------------------------
    # Azure OpenAI (wildcard — matched by suffix)
    # ---------------------------------------------------------------------------
    "*.openai.azure.com": "azure-openai",
    # ---------------------------------------------------------------------------
    # AWS Bedrock (wildcard — matched by pattern)
    # ---------------------------------------------------------------------------
    "bedrock-runtime.us-east-1.amazonaws.com": "aws-bedrock",
    "bedrock-runtime.us-west-2.amazonaws.com": "aws-bedrock",
    "bedrock-runtime.eu-west-1.amazonaws.com": "aws-bedrock",
    "bedrock-runtime.ap-southeast-1.amazonaws.com": "aws-bedrock",
    "bedrock-runtime.ap-northeast-1.amazonaws.com": "aws-bedrock",
    "*.bedrock-runtime.*.amazonaws.com": "aws-bedrock",
    # ---------------------------------------------------------------------------
    # Cohere
    # ---------------------------------------------------------------------------
    "api.cohere.ai": "cohere",
    "api.cohere.com": "cohere",
    "dashboard.cohere.com": "cohere",
    # ---------------------------------------------------------------------------
    # Mistral AI
    # ---------------------------------------------------------------------------
    "api.mistral.ai": "mistral",
    "console.mistral.ai": "mistral",
    # ---------------------------------------------------------------------------
    # Hugging Face
    # ---------------------------------------------------------------------------
    "api-inference.huggingface.co": "huggingface",
    "router.huggingface.co": "huggingface",
    "huggingface.co": "huggingface",
    # ---------------------------------------------------------------------------
    # Replicate
    # ---------------------------------------------------------------------------
    "api.replicate.com": "replicate",
    "replicate.com": "replicate",
    # ---------------------------------------------------------------------------
    # Together AI
    # ---------------------------------------------------------------------------
    "api.together.xyz": "together",
    "api.together.ai": "together",
    # ---------------------------------------------------------------------------
    # Perplexity AI
    # ---------------------------------------------------------------------------
    "api.perplexity.ai": "perplexity",
    "www.perplexity.ai": "perplexity",
    # ---------------------------------------------------------------------------
    # Groq
    # ---------------------------------------------------------------------------
    "api.groq.com": "groq",
    "console.groq.com": "groq",
    # ---------------------------------------------------------------------------
    # DeepSeek
    # ---------------------------------------------------------------------------
    "api.deepseek.com": "deepseek",
    "platform.deepseek.com": "deepseek",
    # ---------------------------------------------------------------------------
    # xAI / Grok
    # ---------------------------------------------------------------------------
    "api.x.ai": "xai",
    "x.ai": "xai",
    # ---------------------------------------------------------------------------
    # Stability AI
    # ---------------------------------------------------------------------------
    "api.stability.ai": "stability",
    "platform.stability.ai": "stability",
    # ---------------------------------------------------------------------------
    # ElevenLabs
    # ---------------------------------------------------------------------------
    "api.elevenlabs.io": "elevenlabs",
    "elevenlabs.io": "elevenlabs",
    # ---------------------------------------------------------------------------
    # Midjourney
    # ---------------------------------------------------------------------------
    "api.midjourney.com": "midjourney",
    "discord.com": "midjourney",  # Midjourney bot channel — ambiguous, flagged for review
    # ---------------------------------------------------------------------------
    # RunwayML
    # ---------------------------------------------------------------------------
    "api.runwayml.com": "runway",
    "runwayml.com": "runway",
    # ---------------------------------------------------------------------------
    # Character AI
    # ---------------------------------------------------------------------------
    "api.character.ai": "character-ai",
    "plus.character.ai": "character-ai",
    # ---------------------------------------------------------------------------
    # OpenRouter (multi-provider proxy)
    # ---------------------------------------------------------------------------
    "openrouter.ai": "openrouter",
    "api.openrouter.ai": "openrouter",
    # ---------------------------------------------------------------------------
    # Fireworks AI
    # ---------------------------------------------------------------------------
    "api.fireworks.ai": "fireworks",
    "app.fireworks.ai": "fireworks",
    # ---------------------------------------------------------------------------
    # Anyscale
    # ---------------------------------------------------------------------------
    "api.endpoints.anyscale.com": "anyscale",
    "console.anyscale.com": "anyscale",
    # ---------------------------------------------------------------------------
    # Lepton AI
    # ---------------------------------------------------------------------------
    "api.lepton.ai": "lepton",
    # ---------------------------------------------------------------------------
    # Aleph Alpha
    # ---------------------------------------------------------------------------
    "api.aleph-alpha.com": "aleph-alpha",
    # ---------------------------------------------------------------------------
    # AI21 Labs
    # ---------------------------------------------------------------------------
    "api.ai21.com": "ai21",
    "studio.ai21.com": "ai21",
    # ---------------------------------------------------------------------------
    # Inflection AI (Pi)
    # ---------------------------------------------------------------------------
    "api.inflection.ai": "inflection",
    "pi.ai": "inflection",
    # ---------------------------------------------------------------------------
    # NovitaAI
    # ---------------------------------------------------------------------------
    "api.novita.ai": "novita",
    # ---------------------------------------------------------------------------
    # Cerebras
    # ---------------------------------------------------------------------------
    "api.cerebras.ai": "cerebras",
    "inference.cerebras.ai": "cerebras",
    # ---------------------------------------------------------------------------
    # Scale AI / Spellbook
    # ---------------------------------------------------------------------------
    "api.scale.com": "scale",
    "spellbook.scale.com": "scale",
    # ---------------------------------------------------------------------------
    # Cohere (Compass / enterprise)
    # ---------------------------------------------------------------------------
    "compass.cohere.com": "cohere",
    # ---------------------------------------------------------------------------
    # Writer
    # ---------------------------------------------------------------------------
    "api.writer.com": "writer",
    "app.writer.com": "writer",
    # ---------------------------------------------------------------------------
    # Jasper AI
    # ---------------------------------------------------------------------------
    "api.jasper.ai": "jasper",
    "app.jasper.ai": "jasper",
    # ---------------------------------------------------------------------------
    # Copy.ai
    # ---------------------------------------------------------------------------
    "api.copy.ai": "copy-ai",
    "app.copy.ai": "copy-ai",
}

# Domains that require wildcard/suffix matching (contain "*")
WILDCARD_AI_PROVIDER_DOMAINS: dict[str, str] = {
    domain: provider
    for domain, provider in AI_PROVIDER_DOMAINS.items()
    if "*" in domain
}

# Exact-match domains (no wildcards)
EXACT_AI_PROVIDER_DOMAINS: dict[str, str] = {
    domain: provider
    for domain, provider in AI_PROVIDER_DOMAINS.items()
    if "*" not in domain
}


def resolve_provider(domain: str) -> str | None:
    """Resolve a domain to its AI provider identifier.

    Attempts exact match first, then wildcard pattern matching for entries
    containing "*" (e.g., "*.openai.azure.com").

    Args:
        domain: The domain to classify (e.g., "my-org.openai.azure.com").

    Returns:
        Provider identifier string if matched, or None if not an AI domain.
    """
    # Exact match
    if domain in EXACT_AI_PROVIDER_DOMAINS:
        return EXACT_AI_PROVIDER_DOMAINS[domain]

    # Wildcard suffix match (e.g., "*.openai.azure.com" matches "foo.openai.azure.com")
    for pattern, provider in WILDCARD_AI_PROVIDER_DOMAINS.items():
        if pattern.startswith("*."):
            suffix = pattern[2:]  # strip "*."
            if domain.endswith(suffix) and domain != suffix:
                return provider
        elif pattern.endswith(".*"):
            prefix = pattern[:-2]  # strip ".*"
            if domain.startswith(prefix + "."):
                return provider

    return None
