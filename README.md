# aumos-shadow-ai-toolkit

Shadow AI discovery, risk assessment, and migration toolkit for AumOS Enterprise.
Detects unauthorized AI tool usage across the enterprise network, quantifies the
$4.63M breach cost risk, and guides employees to governed alternatives.

## Overview

Employees routinely use personal ChatGPT, Claude.ai, Perplexity, and other AI
services without IT knowledge, exposing sensitive enterprise data to unauthorized
third parties. `aumos-shadow-ai-toolkit` operationalizes the governance response:

1. **Discover** — Network traffic analysis identifies AI API calls via DNS patterns,
   TLS SNI, and known endpoint matching. Content is never inspected.
2. **Assess** — Risk scoring (0.0–1.0) combines data sensitivity and compliance
   exposure (GDPR, HIPAA, SOC2) into actionable severity levels.
3. **Migrate** — Guided migration plans offer governed alternatives from the model
   registry, tracked through completion with expiry after 90 days.
4. **Dashboard** — Usage analytics surface adoption trends, risk concentration, and
   migration success rates.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   aumos-shadow-ai-toolkit                   │
│                                                             │
│  api/              core/               adapters/            │
│  ├── router.py     ├── models.py       ├── repositories.py  │
│  └── schemas.py    ├── services.py     ├── kafka.py         │
│                    └── interfaces.py   └── network_scanner  │
└─────────────────────────────────────────────────────────────┘
         ↑                    ↓                    ↓
    FastAPI REST          PostgreSQL           Kafka
    (port 8000)          (sat_ tables)    (SHADOW_AI_EVENTS)
```

**Hexagonal architecture**: The `core/` layer has zero framework imports. Services
depend only on Protocol interfaces (`interfaces.py`). Adapters implement those protocols.

## Quick Start

### Prerequisites

- Python 3.11+
- PostgreSQL 16 with pgvector
- Kafka 3.6+
- Docker (optional)

### Local Development

```bash
# Install dependencies
make install

# Start infrastructure
make docker-run

# Run the service
uvicorn aumos_shadow_ai_toolkit.main:app --reload --port 8000

# Run tests
make test

# Lint and type-check
make lint typecheck
```

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
# Edit .env with your local settings
```

See `.env.example` for all available variables (prefix: `AUMOS_SHADOW_AI_`).

## API Reference

Base URL: `http://localhost:8000/api/v1`

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/shadow-ai/scan` | Initiate a network scan for shadow AI tools |
| `GET` | `/shadow-ai/discoveries` | List all discovered shadow AI tools |
| `GET` | `/shadow-ai/discoveries/{id}` | Discovery detail with risk assessment |
| `GET` | `/shadow-ai/risk-report` | Aggregated risk assessment report |
| `POST` | `/shadow-ai/migrate/{tool_id}` | Start migration workflow |
| `GET` | `/shadow-ai/dashboard` | Usage analytics and adoption dashboard |
| `DELETE` | `/shadow-ai/discoveries/{id}` | Dismiss a discovery |
| `GET` | `/health/live` | Liveness probe |
| `GET` | `/health/ready` | Readiness probe (checks Postgres + Kafka) |

## Database Schema

All tables use the `sat_` prefix and extend `AumOSModel` for tenant isolation.

| Table | Purpose |
|-------|---------|
| `sat_discoveries` | Detected shadow AI tools with risk scores and status |
| `sat_migration_plans` | Migration workflows from shadow to governed tools |
| `sat_scan_results` | Network scan history and per-scan metadata |
| `sat_usage_metrics` | Shadow AI usage analytics aggregated over time |

## Kafka Events

Topic: `SHADOW_AI_EVENTS`

| Event | Trigger |
|-------|---------|
| `shadow_ai.discovered` | New shadow AI tool detected in network scan |
| `shadow_ai.migration_started` | Employee migration workflow initiated |
| `shadow_ai.migration_completed` | Employee successfully migrated to governed tool |

## Risk Scoring

Risk scores are computed as a weighted composite:

```
risk_score = (data_sensitivity_weight * data_sensitivity_score)
           + (compliance_weight * compliance_exposure_score)
```

| Score Range | Severity | Action |
|------------|----------|--------|
| 0.7 – 1.0 | Critical | Immediate block + escalation |
| 0.5 – 0.7 | High | Notify IT Security + 7-day migration SLA |
| 0.3 – 0.5 | Medium | Notify manager + 30-day migration SLA |
| 0.0 – 0.3 | Low | Inform user + 90-day voluntary migration |

## Development

```bash
make install       # Install all dependencies including dev
make test          # Run full test suite with coverage
make test-quick    # Fast test run (fail-fast, no coverage)
make lint          # ruff check + format check
make format        # Auto-fix linting and formatting
make typecheck     # mypy strict type checking
make clean         # Remove build artifacts and caches
```

## License

Apache 2.0 — see [LICENSE](LICENSE)
