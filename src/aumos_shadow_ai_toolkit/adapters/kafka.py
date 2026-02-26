"""Kafka event publishing adapter for the Shadow AI Toolkit service.

Wraps aumos-common's EventPublisher with shadow-ai-domain-specific
topic constants and structured event payloads.
"""

from aumos_common.events import EventPublisher
from aumos_common.observability import get_logger

logger = get_logger(__name__)


class ShadowAIEventPublisher(EventPublisher):
    """Event publisher specialised for shadow AI domain events.

    Extends EventPublisher from aumos-common, adding shadow-ai-specific
    helpers. Topic names follow the shadow_ai.* convention.

    Topics published:
        shadow_ai.discovered           — new shadow AI tool detected in scan
        shadow_ai.migration_started    — employee migration workflow initiated
        shadow_ai.migration_completed  — employee successfully migrated to governed tool
    """

    pass
