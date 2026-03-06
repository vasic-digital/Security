# Course: Security Primitives in Go

## Module Overview

This course covers the `digital.vasic.security` module, providing content validation engines, PII detection and redaction, content filter chains, policy enforcement, security header management, and vulnerability scanning interfaces. The module has zero external runtime dependencies and uses only the Go standard library.

## Prerequisites

- Intermediate Go knowledge (interfaces, regex, crypto)
- Understanding of security concepts (PII, content filtering, policy enforcement)
- Go 1.24+ installed

## Lessons

| # | Title | Duration |
|---|-------|----------|
| 1 | Content Validation with Guardrails Engine | 40 min |
| 2 | PII Detection and Redaction | 45 min |
| 3 | Content Filters and Policy Enforcement | 45 min |
| 4 | Security Headers and Vulnerability Scanning | 35 min |

## Source Files

- `pkg/guardrails/` -- Content validation engine (Chain of Responsibility)
- `pkg/pii/` -- PII detection and redaction (Strategy + Proxy patterns)
- `pkg/content/` -- Content filter chains
- `pkg/policy/` -- Policy enforcement with rule evaluation
- `pkg/headers/` -- Security HTTP headers
- `pkg/scanner/` -- Vulnerability scanning interface
