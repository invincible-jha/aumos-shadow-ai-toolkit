# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Report security vulnerabilities to **security@aumos.ai** (do not open a public issue).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (optional)

We will acknowledge receipt within 48 hours and provide a resolution timeline within 7 days.

## Privacy Commitment

`aumos-shadow-ai-toolkit` performs network metadata analysis only. It **never**:
- Reads or stores request/response content
- Intercepts TLS payload (only SNI hostname inspection)
- Stores API keys or credentials (patterns detected are anonymized immediately)
- Shares discovery data across tenants

Any finding that this service violates these privacy constraints should be treated
as a critical security vulnerability and reported immediately.
