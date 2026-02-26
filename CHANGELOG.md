# Changelog

All notable changes to `aumos-shadow-ai-toolkit` are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.1.0] - 2026-02-26

### Added
- Initial scaffolding with hexagonal architecture (api/, core/, adapters/)
- `DiscoveryService` — detect and track shadow AI tool usage across the enterprise
- `RiskAssessorService` — composite risk scoring by data sensitivity and compliance exposure
- `MigrationService` — guided migration workflows from shadow to governed alternatives
- `NetworkScanner` adapter — DNS pattern matching and TLS SNI analysis for AI API detection
- `ShadowAIEventPublisher` — Kafka event publishing for discovery and migration lifecycle
- SQLAlchemy ORM models with `sat_` prefix: discoveries, migration plans, scan results, usage metrics
- FastAPI REST API with 8 endpoints under `/api/v1/shadow-ai/`
- Risk threshold configuration (critical/high/medium/low) via environment variables
- Usage analytics dashboard endpoint
- PostgreSQL health check via aumos-common
- Multi-stage Docker build with non-root user
- GitHub Actions CI pipeline (lint, typecheck, test)
