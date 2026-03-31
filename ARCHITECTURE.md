# Architecture -- Security

## Purpose

Generic, reusable security module for Go applications. Provides content guardrails with severity-based rules, PII detection and redaction (email, phone, SSN, credit card, IP), composable content filtering chains, rule-based policy enforcement, vulnerability scanning interfaces, HTTP security headers middleware, and AES-256-GCM encrypted file storage.

## Structure

```
pkg/
  guardrails/      Content guardrail engine with configurable rules and severity levels
  pii/             PII detection and redaction with confidence scoring and multiple strategies
  content/         Content filtering with composable chain-of-filters pattern
  policy/          Policy enforcement with rules, conditions, operators, and decisions
  scanner/         Vulnerability scanning interface with findings, reports, and severity filtering
  headers/         HTTP security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
  securestorage/   AES-256-GCM encrypted key-value file storage with credential management
```

## Key Components

- **`guardrails.Engine`** -- Pipeline of rules (MaxLength, ForbiddenPatterns, RequireFormat) with severity levels and optional stop-on-first-failure
- **`pii.Redactor`** -- Combines detectors (Email, Phone, SSN, CreditCard, IP) with redaction strategies (Mask, Hash, Remove)
- **`content.ChainFilter`** -- Composable filter chain: LengthFilter, PatternFilter, KeywordFilter; first rejection wins
- **`policy.Enforcer`** -- Evaluates named policies with rules, conditions (8 operators), and decisions (Allow, Deny, Audit)
- **`scanner.Report`** -- Aggregated vulnerability findings with severity counts, filtering, and report merging
- **`headers.Middleware`** -- Sets 7 standard security headers on all responses
- **`securestorage.FileStorage`** -- AES-256-GCM encrypted files with in-memory cache, credential/token/key helpers

## Data Flow

```
Content validation: input -> guardrails.Check() -> pii.Redact() -> content.ChainFilter.Check()
    |
    guardrails: run rules by severity -> Result{Passed, RuleResults}
    pii: detect matches -> redact with strategy -> cleaned text + matches
    content: run filters in sequence -> first rejection = denied

Policy enforcement: enforcer.Evaluate(ctx, "policy-name", evalCtx)
    |
    for each rule: evaluate conditions -> match? return rule.Decision
    no match -> policy.DefaultDecision

Security headers: headers.Middleware(config)(handler) -> set CSP, HSTS, X-Frame-Options, etc.
```

## Dependencies

- `github.com/stretchr/testify` -- Test assertions (zero production dependencies)

## Testing Strategy

Table-driven tests with `testify` and race detection. Tests cover guardrail rule evaluation, PII detection accuracy and confidence scoring, credit card Luhn validation, filter chain composition, policy condition operators, vulnerability report merging, security header injection, and encrypted storage round-trip verification.
