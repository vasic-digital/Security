# Security Module

`digital.vasic.security` is a standalone, reusable Go module for application security. It provides content guardrails, PII detection and redaction, content filtering, policy enforcement, and vulnerability scanning interfaces -- all with zero external runtime dependencies.

## Key Features

- **Content guardrails** -- Rule-based validation engine that evaluates content against configurable rules (max length, forbidden patterns, required format)
- **PII detection and redaction** -- Detects email addresses, phone numbers, SSNs, credit card numbers, and IP addresses with three redaction strategies (mask, hash, remove)
- **Content filtering** -- Chain-of-filters pattern with length, pattern, and keyword filters
- **Policy enforcement** -- Rule-based policy engine with conditions, operators, and decisions (Allow, Deny, Audit)
- **Vulnerability scanning** -- Interface for pluggable vulnerability scanners with structured findings and reports

## Package Overview

| Package | Purpose |
|---------|---------|
| `pkg/guardrails` | Content validation engine with configurable rules |
| `pkg/pii` | PII detection and redaction (email, phone, SSN, credit card, IP) |
| `pkg/content` | Content filtering with chain-of-filters pattern |
| `pkg/policy` | Policy enforcement with rules, conditions, and decisions |
| `pkg/scanner` | Vulnerability scanning interface |

## Installation

```bash
go get digital.vasic.security
```

Requires Go 1.24 or later.

## Dependencies

Zero external runtime dependencies. The only external dependency is `github.com/stretchr/testify` for tests. Each package under `pkg/` is fully self-contained with no cross-package imports.
