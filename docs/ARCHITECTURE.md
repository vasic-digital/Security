# Architecture - digital.vasic.security

## Design Goals

1. **Standalone and reusable** -- Zero coupling to any application framework. The module depends only on the Go standard library and testify for testing.
2. **Composable** -- Each package is independently usable. Packages can be combined in any order to form security pipelines.
3. **Extensible** -- All core behaviors are defined through small, focused Go interfaces. Users add new functionality by implementing these interfaces rather than modifying existing code.
4. **Thread-safe** -- Components that manage mutable state (guardrails.Engine, policy.Enforcer) use `sync.RWMutex` for safe concurrent access.
5. **Zero external dependencies in production** -- The only external dependency (testify) is test-scoped.

## Module Structure

```
digital.vasic.security/
    go.mod
    pkg/
        guardrails/    -- Content validation engine
        pii/           -- PII detection and redaction
        content/       -- Content filter chains
        policy/        -- Policy enforcement
        scanner/       -- Vulnerability scanning interface
```

Each package under `pkg/` is fully self-contained. There are no cross-package imports within this module.

## Design Patterns

### Chain of Responsibility (content, guardrails)

Both the `content.ChainFilter` and `guardrails.Engine` implement the Chain of Responsibility pattern, where a sequence of handlers each get a chance to process (or reject) input.

**content.ChainFilter**: Filters are evaluated sequentially. The first filter to reject the input short-circuits the chain and returns the rejection result. If all filters pass, the input is allowed.

```
Input --> LengthFilter --> PatternFilter --> KeywordFilter --> Allowed
               |                |                |
               v                v                v
           Rejected         Rejected         Rejected
```

**guardrails.Engine**: Rules are evaluated sequentially. By default, all rules run regardless of failures (collecting all violations). When `StopOnFirstFailure` is enabled, the engine short-circuits on the first violation, behaving as a strict chain.

```
Content --> MaxLengthRule --> ForbiddenPatternsRule --> RequireFormatRule --> Result
                |                    |                       |
                v                    v                       v
           RuleResult           RuleResult              RuleResult
                     \               |                  /
                      +---> Aggregated Result <--------+
```

### Strategy Pattern (pii, policy)

**pii.RedactionStrategy**: The `Redactor` uses a strategy to determine how detected PII is replaced in text. Three strategies are provided:

- **Mask** (`StrategyMask`) -- Replaces characters with a mask character while preserving partial identifying information (e.g., last 4 digits of phone, domain of email).
- **Hash** (`StrategyHash`) -- Replaces the PII value with a truncated SHA-256 hash tagged with the PII type.
- **Remove** (`StrategyRemove`) -- Replaces the PII value with a type-labeled placeholder (e.g., `[EMAIL_REDACTED]`).

The strategy is selected via `Config.RedactionStrategy` and dispatched in `Redactor.redactValue()`.

**policy.Operator**: Condition evaluation uses the Strategy pattern to select comparison logic. Each operator constant (`Equals`, `Contains`, `In`, etc.) maps to a distinct comparison strategy inside `evaluateCondition()`.

**policy.Decision precedence**: When evaluating all policies via `EvaluateAll`, the enforcer uses a strategy for combining results: it keeps the most restrictive decision (`Deny > Audit > Allow`).

### Proxy Pattern (pii.Redactor)

The `pii.Redactor` acts as a proxy that wraps multiple `Detector` instances. The caller interacts with a single `Redactor`, which internally delegates detection to the configured set of detectors and then applies the configured redaction strategy. This decouples detection from redaction:

```
Caller --> Redactor.Redact()
               |
               +--> EmailDetector.Detect()
               +--> PhoneDetector.Detect()
               +--> SSNDetector.Detect()
               |
               +--> Apply redaction strategy to all matches
               |
               v
           Redacted text + Match list
```

### Interface Segregation

Each package defines the smallest possible interface for its extension point:

| Interface | Package | Methods | Purpose |
|-----------|---------|---------|---------|
| `Rule` | guardrails | `Name()`, `Check()` | Content validation rule |
| `Detector` | pii | `Detect()` | PII pattern detector |
| `Filter` | content | `Check()` | Content filter |
| `Scanner` | scanner | `Scan()` | Vulnerability scanner |

This makes it trivial to add new implementations without modifying existing code.

## Concurrency Model

### Thread-Safe Components

- **guardrails.Engine**: Uses `sync.RWMutex`. `AddRule()` acquires a write lock; `Check()` acquires a read lock, copies the rule slice, then releases the lock before evaluating rules.
- **policy.Enforcer**: Uses `sync.RWMutex`. `LoadPolicy()` and `RemovePolicy()` acquire write locks; `Evaluate()`, `EvaluateAll()`, and `GetPolicy()` acquire read locks.

### Stateless Components

- **pii.Redactor**: Immutable after construction. Detectors are stateless. Safe for concurrent use without synchronization.
- **content.ChainFilter**: Filters are stateless. The filter list is only mutable via `AddFilter()`. If filters are not added after construction, the chain is safe for concurrent reads.
- **scanner.Report**: Value type with no mutation methods. Safe for concurrent reads.

## Error Handling

The module follows Go conventions for error handling:

- **Constructor errors**: Functions like `NewForbiddenPatternsRule()` and `NewPatternFilter()` return `(T, error)` when the input could be invalid (e.g., malformed regex).
- **Check/evaluation errors**: `content.Filter.Check()` returns `(FilterResult, error)` to distinguish between filter rejection (a business result) and infrastructure errors.
- **Scanner errors**: `Scanner.Scan()` returns `([]Finding, error)`. `RunScanner()` wraps scanner errors with the scanner name for context.
- **Policy loading errors**: `LoadPolicy()` validates that the policy is non-nil and has a name. `LoadPolicies()` wraps individual load errors with the policy name.
- **Guardrail rule errors**: Rule violations are returned as `error` from `Rule.Check()`, then captured as strings in `RuleResult.Error`. This allows the engine to collect all violations rather than stopping at the first `error`.

## Data Flow Patterns

### Guardrail Evaluation Flow

1. Engine receives content string
2. Engine iterates registered rules (under read lock)
3. For each enabled rule, `Check()` is called
4. Results are collected into `Result.Results` with severity from config
5. If any rule fails, `Result.Passed` is set to false
6. If `StopOnFirstFailure` is set, evaluation stops at first failure

### PII Redaction Flow

1. Redactor receives text string
2. Each enabled detector scans the full text independently
3. All matches are collected and sorted by start position (descending)
4. Descending sort ensures that replacing from the end of the string first preserves earlier match positions
5. Each match is replaced according to the configured redaction strategy
6. Redacted text and original matches are returned

### Policy Evaluation Flow

1. Enforcer receives policy name and evaluation context
2. Policy rules are iterated in order
3. For each rule, all conditions must match (AND logic)
4. The first rule where all conditions match determines the decision
5. If no rules match, the policy's default decision is used
6. For `EvaluateAll`, the most restrictive decision across all policies wins

## Testing Strategy

All packages use table-driven tests with `testify/assert` and `testify/require`. Key testing patterns:

- **Boundary testing**: Length limits, empty inputs, exact-boundary values
- **Concurrency testing**: `TestEngine_ConcurrentAccess` verifies thread safety with 10 goroutines x 100 iterations
- **Error path testing**: Invalid regex patterns, nil policies, missing policy names
- **Strategy testing**: Each PII redaction strategy (mask, hash, remove) is tested independently
- **Operator coverage**: Every policy operator has dedicated test cases
- **Integration testing**: Multi-rule engines, multi-filter chains, multi-policy evaluation
