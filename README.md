# Security

Generic, reusable security module for Go applications.

## Packages

### pkg/guardrails
Content guardrail engine with configurable rules, severity levels, and a pipeline for chaining multiple guardrails.

### pkg/pii
PII detection and redaction with built-in detectors for email, phone, SSN, credit card, and IP address patterns. Supports mask, hash, and remove redaction strategies.

### pkg/content
Content filtering with composable filter chains. Built-in filters include length, pattern, and keyword filters.

### pkg/policy
Policy enforcement framework with rules, conditions, operators, and decisions (Allow, Deny, Audit).

### pkg/scanner
Vulnerability scanning interface with severity levels, findings, and aggregated reports.

## Usage

```go
import (
    "digital.vasic.security/pkg/guardrails"
    "digital.vasic.security/pkg/pii"
    "digital.vasic.security/pkg/content"
    "digital.vasic.security/pkg/policy"
    "digital.vasic.security/pkg/scanner"
)
```

## Testing

```bash
go test ./... -count=1 -race
```
