# CLAUDE.md — AumOS Shadow AI Toolkit

## Project Overview

AumOS Enterprise is a composable enterprise AI platform with 9 products + 2 services
across 62 repositories. This repo (`aumos-shadow-ai-toolkit`) is part of **Product 5:
People & Adoption**: Discover, assess, and migrate unauthorized AI tool usage across
the enterprise, operationalizing the $4.63M breach cost risk from shadow AI.

**Release Tier:** B: Open Core
**Product Mapping:** Product 5 — People & Adoption
**Phase:** 3 (Months 10-16)

## Repo Purpose

Implements a network traffic scanner and risk assessment engine to detect employees
using unauthorized AI services (ChatGPT personal, Claude.ai, Perplexity, etc.) outside
sanctioned enterprise channels. Provides risk scoring by data sensitivity and compliance
exposure, guided migration workflows to move users from shadow tools to governed
alternatives, and a usage analytics dashboard.

## Architecture Position

```
Network Traffic     → aumos-shadow-ai-toolkit → aumos-governance-engine (risk policy)
aumos-common       ↗                          ↘ aumos-model-registry (governed alternatives)
aumos-proto        ↗                          ↘ Kafka (shadow_ai.* events)
                                              ↘ aumos-approval-workflow (migration approvals)
```

**Upstream dependencies (this repo IMPORTS from):**
- `aumos-common` — auth, database, events, errors, config, health, pagination
- `aumos-proto` — Protobuf message definitions for Kafka events
- `aumos-governance-engine` — risk policy evaluation (UUID references, no FK)

**Downstream dependents (other repos IMPORT from this):**
- `aumos-model-registry` — source of governed alternatives offered in migration
- `aumos-approval-workflow` — gates migration workflows through stakeholder approval

## Tech Stack (DO NOT DEVIATE)

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.110+ | REST API framework |
| SQLAlchemy | 2.0+ (async) | Database ORM |
| asyncpg | 0.29+ | PostgreSQL async driver |
| Pydantic | 2.6+ | Data validation, settings, API schemas |
| httpx | 0.27+ | Async HTTP for network scanner and upstream services |
| confluent-kafka | 2.3+ | Kafka producer/consumer via aumos-common |
| structlog | 24.1+ | Structured JSON logging |
| OpenTelemetry | 1.23+ | Distributed tracing |
| pytest | 8.0+ | Testing framework |
| ruff | 0.3+ | Linting and formatting |
| mypy | 1.8+ | Type checking |

## Coding Standards

### ABSOLUTE RULES (violations will break integration with other repos)

1. **Import aumos-common, never reimplement.** If aumos-common provides it, use it.
   ```python
   # CORRECT
   from aumos_common.auth import get_current_tenant, get_current_user
   from aumos_common.database import get_db_session, Base, AumOSModel, BaseRepository
   from aumos_common.events import EventPublisher, Topics
   from aumos_common.errors import NotFoundError, ErrorCode
   from aumos_common.config import AumOSSettings
   from aumos_common.health import create_health_router
   from aumos_common.pagination import PageRequest, PageResponse, paginate
   from aumos_common.app import create_app

   # WRONG — never reimplement these
   # from jose import jwt
   # from sqlalchemy import create_engine
   # import logging
   ```

2. **Type hints on EVERY function.** No exceptions.

3. **Pydantic models for ALL API inputs/outputs.** Never return raw dicts.

4. **RLS tenant isolation via aumos-common.** Never write raw SQL that bypasses RLS.

5. **Structured logging via structlog.** Never use print() or logging.getLogger().

6. **Publish domain events to Kafka after state changes.**

7. **Async by default.** All I/O operations must be async.

8. **Google-style docstrings** on all public classes and functions.

### Shadow AI Domain Rules

- **Risk scoring**: Every discovered tool receives a composite risk score (0.0–1.0) based
  on data sensitivity (what types of data users send) and compliance exposure (GDPR, HIPAA,
  SOC2). Risk scores above 0.7 are `critical`, 0.5–0.7 `high`, 0.3–0.5 `medium`, below
  0.3 `low`.

- **Detection methods**: The network scanner identifies shadow AI tools via:
  1. DNS resolution matching known AI API endpoints
  2. TLS SNI inspection (domain-level, not content)
  3. HTTP CONNECT tunnel analysis
  4. Known API key patterns in Authorization headers (sanitized, not stored)

- **Migration workflow**: The MigrationService creates a migration plan offering a
  governed alternative from the model registry, triggers an approval workflow, and
  tracks employee adoption. Migration plans expire after 90 days if not acted on.

- **No content inspection**: The scanner NEVER reads or stores actual request/response
  content — only metadata (destination, frequency, estimated data volume). This is a
  strict privacy boundary.

- **Discovery status lifecycle**: `detected` → `assessed` → `notified` → `migrating`
  → `migrated` or `dismissed`

### File Structure Convention

```
src/aumos_shadow_ai_toolkit/
├── __init__.py
├── main.py                         # FastAPI app entry point using create_app()
├── settings.py                     # Extends AumOSSettings with AUMOS_SHADOW_AI_ prefix
├── api/                            # FastAPI routes (thin layer — delegates to services)
│   ├── __init__.py
│   ├── router.py                   # All endpoints
│   └── schemas.py                  # Pydantic request/response models
├── core/                           # Business logic (no framework dependencies)
│   ├── __init__.py
│   ├── models.py                   # SQLAlchemy ORM models (sat_ prefix)
│   ├── interfaces.py               # Protocol classes for dependency injection
│   └── services.py                 # DiscoveryService, RiskAssessorService, MigrationService
└── adapters/
    ├── __init__.py
    ├── repositories.py             # SQLAlchemy repositories (extend BaseRepository)
    ├── kafka.py                    # Shadow AI event publishing
    └── network_scanner.py          # Network traffic analysis for AI API calls
tests/
├── __init__.py
├── conftest.py
└── test_services.py
```

## API Conventions

- All endpoints under `/api/v1/shadow-ai/` prefix
- Auth: Bearer JWT token (validated by aumos-common)
- Tenant: `X-Tenant-ID` header (set by auth middleware)
- Request ID: `X-Request-ID` header (auto-generated if missing)
- Pagination: `?page=1&page_size=20&sort_by=created_at&sort_order=desc`
- Errors: Standard `ErrorResponse` from aumos-common
- Content-Type: `application/json` (always)

## Database Conventions

- Table prefix: `sat_` (e.g., `sat_discoveries`, `sat_migration_plans`)
- ALL tenant-scoped tables: extend `AumOSModel` (gets id, tenant_id, created_at, updated_at)
- RLS policy on every tenant table (created in migration)
- Foreign keys to other repos' tables: use UUID type, no FK constraints (cross-service)

## Kafka Conventions

- Publish events via `EventPublisher` from aumos-common
- Use `Topics.*` constants for topic names
- Topic: `SHADOW_AI_EVENTS`
- Events: `shadow_ai.discovered`, `shadow_ai.migration_started`, `shadow_ai.migration_completed`
- Always include `tenant_id` and `correlation_id` in events

## Environment Variables

All standard env vars are defined in `aumos_common.config.AumOSSettings`.
Repo-specific vars use the prefix `AUMOS_SHADOW_AI_`.

Key environment variables:
- `AUMOS_SHADOW_AI_SCAN_INTERVAL_SECONDS` — How often to run network scans (default: 3600)
- `AUMOS_SHADOW_AI_KNOWN_AI_ENDPOINTS` — JSON list of known AI API domains to detect
- `AUMOS_SHADOW_AI_RISK_THRESHOLD_CRITICAL` — Risk score threshold for critical rating (default: 0.7)
- `AUMOS_SHADOW_AI_MIGRATION_EXPIRY_DAYS` — Days before migration plan expires (default: 90)
- `AUMOS_SHADOW_AI_GOVERNANCE_ENGINE_URL` — URL for governance-engine policy evaluation
- `AUMOS_SHADOW_AI_MODEL_REGISTRY_URL` — URL for model-registry governed alternatives lookup

## What Claude Code Should NOT Do

1. **Do NOT reimplement anything in aumos-common.** Use JWT parsing, tenant context,
   DB sessions, Kafka publishing, error handling, logging, health checks, and pagination
   from aumos-common exclusively.
2. **Do NOT use print().** Use `get_logger(__name__)`.
3. **Do NOT return raw dicts from API endpoints.** Use Pydantic models.
4. **Do NOT write raw SQL.** Use SQLAlchemy ORM with BaseRepository.
5. **Do NOT hardcode configuration.** Use Pydantic Settings with env vars.
6. **Do NOT skip type hints.** Every function signature must be typed.
7. **Do NOT store request/response content** from scanned network traffic. Metadata only.
8. **Do NOT put business logic in API routes.** Routes call services; services contain logic.
9. **Do NOT create new exception classes** unless they map to a new ErrorCode in aumos-common.
10. **Do NOT bypass RLS.** All discovery and migration queries must be tenant-scoped.
