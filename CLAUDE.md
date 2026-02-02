# CLAUDE.md - Security Module

## Overview

`digital.vasic.security` is a standalone, reusable Go security module providing content guardrails, PII detection and redaction, content filtering, policy enforcement, and vulnerability scanning interfaces.

## Module Structure

- `pkg/guardrails` - Content guardrail engine with configurable rules
- `pkg/pii` - PII detection and redaction (email, phone, SSN, credit card, IP)
- `pkg/content` - Content filtering with chain-of-filters pattern
- `pkg/policy` - Policy enforcement with rules, conditions, and decisions
- `pkg/scanner` - Vulnerability scanning interface with findings and reports

## Build & Test

```bash
go test ./... -count=1 -race    # Run all tests with race detection
go test ./... -cover             # Run with coverage
go vet ./...                     # Vet all packages
```

## Code Style

- Standard Go conventions, `gofmt` formatting
- Imports grouped: stdlib, third-party, internal
- Table-driven tests with testify
- Interfaces: small, focused, accept interfaces return structs
- Errors: always check, wrap with `fmt.Errorf("...: %w", err)`

## Dependencies

- `github.com/stretchr/testify` - Testing assertions
- No other external dependencies
- No dependency on HelixAgent
