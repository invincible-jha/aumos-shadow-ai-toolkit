"""Migration Proposal Service — AumOS module proposal engine.

Generates structured migration proposals for detected shadow AI usage,
mapping observed patterns (code-assist, text-generation, data-analysis, etc.)
to the most appropriate AumOS governed module with complexity and effort estimates.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from aumos_common.observability import get_logger

from aumos_shadow_ai_toolkit.core.models.shadow_detection import (
    ShadowAIDetection,
    ShadowMigrationProposal,
)

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Shadow-to-AumOS module mapping registry
# ---------------------------------------------------------------------------

# Each key is a business_value_indicator from ShadowAIDetection.
# Each value is a dict with the target AumOS module and migration metadata.
SHADOW_TO_AUMOS_MAPPING: dict[str, dict[str, Any]] = {
    "code-assist": {
        "module": "aumos-llm-serving",
        "complexity": "trivial",
        "hours": Decimal("2.0"),
        "preservation_pct": Decimal("95.00"),
        "description": (
            "Route code assistance through governed LLM serving with full audit trail, "
            "model governance policies, and data residency controls."
        ),
    },
    "text-generation": {
        "module": "aumos-text-engine",
        "complexity": "moderate",
        "hours": Decimal("8.0"),
        "preservation_pct": Decimal("90.00"),
        "description": (
            "Replace direct API calls with AumOS text engine supporting PII detection, "
            "differential privacy output filtering, and structured output validation."
        ),
    },
    "data-analysis": {
        "module": "aumos-context-graph",
        "complexity": "moderate",
        "hours": Decimal("16.0"),
        "preservation_pct": Decimal("85.00"),
        "description": (
            "Migrate analytics workflows to graph-accelerated RAG with data governance, "
            "fine-grained access control, and provenance tracking."
        ),
    },
    "image-generation": {
        "module": "aumos-image-engine",
        "complexity": "moderate",
        "hours": Decimal("4.0"),
        "preservation_pct": Decimal("90.00"),
        "description": (
            "Route image generation through governed pipeline with C2PA provenance "
            "watermarking, content policy enforcement, and brand safety filters."
        ),
    },
    "productivity": {
        "module": "aumos-llm-serving",
        "complexity": "trivial",
        "hours": Decimal("4.0"),
        "preservation_pct": Decimal("92.00"),
        "description": (
            "Replace general productivity AI usage with governed LLM serving endpoint "
            "featuring session management, rate limiting, and usage analytics."
        ),
    },
    "audio": {
        "module": "aumos-audio-engine",
        "complexity": "moderate",
        "hours": Decimal("8.0"),
        "preservation_pct": Decimal("88.00"),
        "description": (
            "Migrate audio AI usage (transcription, TTS) to AumOS audio engine with "
            "speaker anonymisation support and DLP scanning on transcripts."
        ),
    },
    "video": {
        "module": "aumos-video-engine",
        "complexity": "complex",
        "hours": Decimal("24.0"),
        "preservation_pct": Decimal("80.00"),
        "description": (
            "Migrate video AI processing to AumOS video engine with content provenance, "
            "deepfake detection, and governed frame-level analysis."
        ),
    },
    "embedding": {
        "module": "aumos-context-graph",
        "complexity": "moderate",
        "hours": Decimal("12.0"),
        "preservation_pct": Decimal("88.00"),
        "description": (
            "Replace external embedding API calls with AumOS context graph embedding "
            "service supporting private vector stores and tenant isolation."
        ),
    },
    "fine-tuning": {
        "module": "aumos-llm-serving",
        "complexity": "complex",
        "hours": Decimal("40.0"),
        "preservation_pct": Decimal("75.00"),
        "description": (
            "Migrate fine-tuning workflows to governed MLOps lifecycle with model "
            "registry integration, training data governance, and bias evaluation."
        ),
    },
    "document-processing": {
        "module": "aumos-text-engine",
        "complexity": "moderate",
        "hours": Decimal("10.0"),
        "preservation_pct": Decimal("90.00"),
        "description": (
            "Replace AI document processing with AumOS text engine OCR and "
            "extraction capabilities featuring DLP and classification enforcement."
        ),
    },
    "search": {
        "module": "aumos-context-graph",
        "complexity": "moderate",
        "hours": Decimal("8.0"),
        "preservation_pct": Decimal("87.00"),
        "description": (
            "Migrate semantic search to AumOS context graph with tenant-scoped "
            "vector store, access control policies, and audit logging."
        ),
    },
    "summarisation": {
        "module": "aumos-text-engine",
        "complexity": "trivial",
        "hours": Decimal("4.0"),
        "preservation_pct": Decimal("92.00"),
        "description": (
            "Replace summarisation API calls with AumOS text engine endpoints "
            "that apply length and sensitivity-level constraints per tenant policy."
        ),
    },
    "translation": {
        "module": "aumos-text-engine",
        "complexity": "trivial",
        "hours": Decimal("3.0"),
        "preservation_pct": Decimal("95.00"),
        "description": (
            "Route translation requests through AumOS text engine translation "
            "service with content classification and jurisdictional compliance."
        ),
    },
    "classification": {
        "module": "aumos-context-graph",
        "complexity": "moderate",
        "hours": Decimal("14.0"),
        "preservation_pct": Decimal("86.00"),
        "description": (
            "Migrate AI classification tasks to AumOS context graph with governed "
            "label taxonomies, confidence thresholds, and explainability reports."
        ),
    },
    "unknown": {
        "module": "aumos-llm-serving",
        "complexity": "moderate",
        "hours": Decimal("8.0"),
        "preservation_pct": Decimal("85.00"),
        "description": (
            "Route unclassified AI API usage through governed LLM serving endpoint. "
            "Usage pattern will be further analysed during migration planning."
        ),
    },
}

# ---------------------------------------------------------------------------
# Summary dataclass
# ---------------------------------------------------------------------------


@dataclass
class MigrationSummary:
    """Aggregated migration effort summary across multiple detections.

    Attributes:
        total_detections: Number of shadow AI detections included.
        total_estimated_hours: Sum of estimated migration hours.
        complexity_breakdown: Count of detections by complexity tier.
        module_breakdown: Count of proposals targeting each AumOS module.
        average_preservation_pct: Mean productivity preservation percentage.
        proposals: All generated ShadowMigrationProposal instances.
    """

    total_detections: int
    total_estimated_hours: Decimal
    complexity_breakdown: dict[str, int]
    module_breakdown: dict[str, int]
    average_preservation_pct: Decimal
    proposals: list[ShadowMigrationProposal]


# ---------------------------------------------------------------------------
# Service implementation
# ---------------------------------------------------------------------------


class MigrationProposalService:
    """Generates AumOS module migration proposals for shadow AI detections.

    Each proposal maps a detected shadow AI usage pattern to the most
    appropriate AumOS module, estimating complexity, hours, and expected
    productivity preservation after migration.
    """

    async def generate_proposal(
        self, detection: ShadowAIDetection
    ) -> ShadowMigrationProposal:
        """Generate a migration proposal based on the detected usage pattern.

        Selects the AumOS module mapping based on the detection's
        business_value_indicator. Falls back to "unknown" mapping if the
        indicator is not in the registry.

        Args:
            detection: The ShadowAIDetection to generate a proposal for.

        Returns:
            Unsaved ShadowMigrationProposal for the detection.
        """
        indicator = detection.business_value_indicator or "unknown"
        mapping = SHADOW_TO_AUMOS_MAPPING.get(indicator, SHADOW_TO_AUMOS_MAPPING["unknown"])

        proposal = ShadowMigrationProposal.__new__(ShadowMigrationProposal)
        proposal.id = uuid.uuid4()
        proposal.tenant_id = detection.tenant_id
        proposal.detection_id = detection.id
        proposal.proposed_aumos_module = mapping["module"]
        proposal.migration_complexity = mapping["complexity"]
        proposal.estimated_migration_hours = mapping["hours"]
        proposal.productivity_preservation_pct = mapping["preservation_pct"]
        proposal.compliance_gain_description = mapping["description"]
        proposal.created_at = datetime.now(tz=timezone.utc)
        proposal.updated_at = datetime.now(tz=timezone.utc)

        logger.info(
            "Migration proposal generated",
            tenant_id=str(detection.tenant_id),
            detection_id=str(detection.id),
            provider=detection.provider,
            indicator=indicator,
            module=mapping["module"],
            complexity=mapping["complexity"],
            hours=str(mapping["hours"]),
        )

        return proposal

    async def estimate_total_migration(
        self, detections: list[ShadowAIDetection]
    ) -> MigrationSummary:
        """Aggregate migration effort across all provided detections.

        Generates one proposal per detection and accumulates totals for
        hours, complexity tiers, and module distribution.

        Args:
            detections: List of ShadowAIDetection instances to evaluate.

        Returns:
            MigrationSummary with aggregate totals and all proposals.
        """
        proposals: list[ShadowMigrationProposal] = []
        total_hours = Decimal("0.0")
        total_preservation = Decimal("0.00")
        complexity_breakdown: dict[str, int] = {
            "trivial": 0,
            "moderate": 0,
            "complex": 0,
        }
        module_breakdown: dict[str, int] = {}

        for detection in detections:
            proposal = await self.generate_proposal(detection)
            proposals.append(proposal)

            total_hours += proposal.estimated_migration_hours
            total_preservation += proposal.productivity_preservation_pct

            complexity = proposal.migration_complexity
            complexity_breakdown[complexity] = complexity_breakdown.get(complexity, 0) + 1

            module = proposal.proposed_aumos_module
            module_breakdown[module] = module_breakdown.get(module, 0) + 1

        average_preservation = (
            total_preservation / Decimal(len(detections))
            if detections
            else Decimal("0.00")
        )

        logger.info(
            "Migration effort estimate complete",
            total_detections=len(detections),
            total_hours=str(total_hours),
            complexity_breakdown=complexity_breakdown,
        )

        return MigrationSummary(
            total_detections=len(detections),
            total_estimated_hours=total_hours,
            complexity_breakdown=complexity_breakdown,
            module_breakdown=module_breakdown,
            average_preservation_pct=round(average_preservation, 2),
            proposals=proposals,
        )
