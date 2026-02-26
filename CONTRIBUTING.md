# Contributing to aumos-shadow-ai-toolkit

## Development Setup

```bash
git clone <repo-url>
cd aumos-shadow-ai-toolkit
make install
cp .env.example .env
make docker-run
```

## Code Standards

- Python 3.11+ with full type hints on all function signatures
- `ruff` for linting and formatting (line length 120)
- `mypy` strict mode — no `Any`, no untyped functions
- Google-style docstrings on all public classes and functions
- Tests alongside implementation (minimum 80% coverage)

## Conventional Commits

```
feat:      New feature
fix:       Bug fix
refactor:  Code restructure without behavior change
test:      Add or update tests
docs:      Documentation changes
chore:     Build, CI, or dependency updates
```

## Pull Request Process

1. Branch from `main`: `feature/`, `fix/`, `docs/`
2. Run `make all` (lint + typecheck + test) before pushing
3. Write tests for any new business logic in `core/services.py`
4. Update `CHANGELOG.md` under `[Unreleased]`
5. Request review from a maintainer

## Privacy Rules

**Never** inspect, log, or store the content of network requests being scanned.
Only metadata (destination domain, frequency, estimated data volume) is permitted.
This is a legal and compliance requirement — violations will be rejected immediately.
