# Security

Generic, reusable security module for Go applications. Provides content guardrails, PII detection and redaction, content filtering with composable chains, policy enforcement, vulnerability scanning, HTTP security headers middleware, and AES-256-GCM encrypted file storage.

**Module**: `digital.vasic.security` (Go 1.24+)

## Architecture

The module follows a layered security approach where each package addresses a specific security concern independently. Packages can be composed together for defense-in-depth: content flows through guardrails, then PII redaction, then content filters, with policy enforcement governing access decisions. The scanner package provides vulnerability assessment, while headers and securestorage handle transport and data-at-rest security.

```
pkg/
  guardrails/      Content guardrail engine with configurable rules and severity
  pii/             PII detection and redaction (email, phone, SSN, credit card, IP)
  content/         Content filtering with composable filter chains
  policy/          Policy enforcement with rules, conditions, and decisions
  scanner/         Vulnerability scanning interface with reports
  headers/         HTTP security headers middleware
  securestorage/   AES-256-GCM encrypted key-value file storage
```

## Package Reference

### pkg/guardrails -- Content Guardrail Engine

Validates content against a pipeline of configurable rules with severity levels.

**Types:**
- `Severity` -- SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo.
- `Rule` -- Interface with `Name() string` and `Check(content string) error`.
- `RuleConfig` -- Per-rule Enabled flag and Severity level.
- `Config` -- Map of rule configurations and StopOnFirstFailure option.
- `RuleResult` -- Individual rule check result (RuleName, Passed, Severity, Error).
- `Result` -- Aggregate result with overall Passed flag and slice of RuleResults.
- `Engine` -- Manages and executes rules.

**Built-in Rules:**
- `MaxLengthRule` -- Rejects content exceeding a character limit.
- `ForbiddenPatternsRule` -- Rejects content matching forbidden regex patterns.
- `RequireFormatRule` -- Requires content to match a specific regex format.

**Key Functions:**
- `NewEngine(config *Config) *Engine` -- Creates a guardrail engine.
- `Engine.AddRule(rule Rule)` -- Adds a rule to the pipeline.
- `Engine.Check(content string) *Result` -- Runs all enabled rules and returns the aggregate result.
- `NewMaxLengthRule(maxLength int) *MaxLengthRule`
- `NewForbiddenPatternsRule(patterns map[string]string) (*ForbiddenPatternsRule, error)`
- `NewRequireFormatRule(formatName, pattern string) (*RequireFormatRule, error)`

### pkg/pii -- PII Detection and Redaction

Detects and redacts personally identifiable information with configurable strategies and confidence scoring.

**Types:**
- `Type` -- TypeEmail, TypePhone, TypeSSN, TypeCreditCard, TypeIPAddress.
- `Match` -- Detected PII with Type, Value, Start/End positions, and Confidence score.
- `Detector` -- Interface with `Detect(text string) []Match`.
- `RedactionStrategy` -- StrategyMask (partial masking), StrategyHash (SHA-256 hash), StrategyRemove (type placeholder).
- `Config` -- EnabledDetectors, RedactionStrategy, MaskChar.
- `Redactor` -- Combines detection and redaction.

**Built-in Detectors:**
- `EmailDetector()` -- Email addresses (confidence 0.9).
- `PhoneDetector()` -- US phone numbers (confidence 0.8).
- `SSNDetector()` -- Social Security Numbers (confidence 0.85).
- `CreditCardDetector()` -- Credit cards with Luhn validation (confidence 0.7-0.95).
- `IPAddressDetector()` -- IPv4 addresses (confidence 0.75).

**Key Functions:**
- `NewRedactor(config *Config) *Redactor` -- Creates a redactor with selected detectors.
- `Redactor.Detect(text string) []Match` -- Detects all PII in text.
- `Redactor.Redact(text string) (string, []Match)` -- Redacts PII and returns the cleaned text with matches.

### pkg/content -- Content Filtering

Composable content filter chains where content must pass all filters to be allowed.

**Types:**
- `FilterResult` -- Allowed flag, Reason string, and Score (0.0-1.0).
- `Filter` -- Interface with `Check(input string) (FilterResult, error)`.
- `ChainFilter` -- Combines multiple filters; first rejection wins.

**Built-in Filters:**
- `LengthFilter` -- Enforces minimum and maximum input length.
- `PatternFilter` -- Rejects content matching forbidden regex patterns (score 0.9).
- `KeywordFilter` -- Rejects content containing blocked keywords with optional case sensitivity (score 0.8).

**Key Functions:**
- `NewChainFilter(filters ...Filter) *ChainFilter` -- Creates a filter chain.
- `ChainFilter.AddFilter(filter Filter)` -- Appends a filter to the chain.
- `ChainFilter.Check(input string) (FilterResult, error)` -- Runs all filters in sequence.
- `NewLengthFilter(minLength, maxLength int) *LengthFilter`
- `NewPatternFilter(patterns map[string]string) (*PatternFilter, error)`
- `NewKeywordFilter(keywords []string, caseSensitive bool) *KeywordFilter`

### pkg/policy -- Policy Enforcement

Rule-based policy enforcement with conditions, operators, and decisions (Allow, Deny, Audit).

**Types:**
- `Decision` -- DecisionAllow, DecisionDeny, DecisionAudit.
- `Operator` -- OperatorEquals, OperatorNotEquals, OperatorContains, OperatorStartsWith, OperatorEndsWith, OperatorIn, OperatorNotIn, OperatorExists, OperatorNotExists.
- `Condition` -- Field, Operator, Value/Values for matching.
- `Rule` -- Named rule with Conditions and a Decision.
- `Policy` -- Named collection of rules with a DefaultDecision.
- `EvaluationResult` -- Decision, MatchedRule, and Reason.
- `EvaluationContext` -- Map of field names to values for condition evaluation.
- `Enforcer` -- Loads, manages, and evaluates policies.

**Key Functions:**
- `NewEnforcer() *Enforcer` -- Creates a policy enforcer.
- `Enforcer.LoadPolicy(policy *Policy) error` -- Adds a policy.
- `Enforcer.LoadPolicies(policies []*Policy) error` -- Adds multiple policies.
- `Enforcer.Evaluate(ctx, policyName, evalCtx) (*EvaluationResult, error)` -- Evaluates a specific policy.
- `Enforcer.EvaluateAll(ctx, evalCtx) (*EvaluationResult, error)` -- Evaluates all policies; returns the most restrictive decision (Deny > Audit > Allow).
- `Enforcer.RemovePolicy(name)` / `Enforcer.GetPolicy(name)`

### pkg/scanner -- Vulnerability Scanning

Interface and reporting for vulnerability scanning with severity-based filtering and report merging.

**Types:**
- `Severity` -- SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo.
- `Finding` -- Severity, Title, Description, Location, CWE, and Remediation.
- `Scanner` -- Interface with `Scan(ctx, target string) ([]Finding, error)`.
- `Report` -- Aggregated findings with BySeverity counts, Duration, and ScannedAt.

**Key Functions:**
- `NewReport(findings, scannerName, target, duration) *Report` -- Creates a report from findings.
- `Report.HasCritical() bool` / `Report.HasHighOrAbove() bool` -- Severity checks.
- `Report.FilterBySeverity(minSeverity Severity) []Finding` -- Filters findings by minimum severity.
- `Report.Summary() string` -- Human-readable summary with counts per severity.
- `RunScanner(ctx, scanner, name, target) (*Report, error)` -- Runs a scanner and produces a timed report.
- `MergeReports(reports ...*Report) *Report` -- Merges multiple reports into one.

### pkg/headers -- HTTP Security Headers

Middleware that sets standard security headers on every HTTP response.

**Headers set by default:**
- `Content-Security-Policy: default-src 'self'`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: geolocation=(), camera=(), microphone=()`
- `X-XSS-Protection: 1; mode=block`

**Key Functions:**
- `DefaultConfig() Config` -- Returns sensible security defaults.
- `Middleware(cfg Config) func(http.Handler) http.Handler` -- Returns middleware that sets configured headers. Empty config values are skipped.

### pkg/securestorage -- Encrypted File Storage

AES-256-GCM encrypted key-value storage backed by files. Thread-safe with automatic key generation and caching.

**Types:**
- `Storage` -- Interface with Store, Retrieve, Delete, Contains, ListKeys, Clear, IsSecure methods.
- `FileStorage` -- Implementation using encrypted files with in-memory cache.

**Key Functions:**
- `NewFileStorage(storageDir string) *FileStorage` -- Creates storage at the given directory.
- `FileStorage.Store(key, value string) error` / `FileStorage.Retrieve(key string) (string, error)`
- `FileStorage.Delete(key string) error` / `FileStorage.Contains(key string) (bool, error)`
- `FileStorage.ListKeys() ([]string, error)` / `FileStorage.Clear() error`
- `FileStorage.IsSecure() (bool, error)` -- Verifies encryption round-trip works.
- `FileStorage.StoreCredentials(service, username, password) error` -- Stores credentials with length-prefixed format.
- `FileStorage.RetrieveCredentials(service string) (username, password string, err error)`
- `FileStorage.StoreToken(service, token) error` / `FileStorage.RetrieveToken(service) (string, error)`
- `FileStorage.StorePrivateKey(service, key) error` / `FileStorage.RetrievePrivateKey(service) (string, error)`

## Usage Examples

### Content Guardrails

```go
engine := guardrails.NewEngine(&guardrails.Config{
    StopOnFirstFailure: true,
})
engine.AddRule(guardrails.NewMaxLengthRule(10000))

patterns, _ := guardrails.NewForbiddenPatternsRule(map[string]string{
    "sql_injection": `(?i)(drop|delete|truncate)\s+table`,
    "script_tag":    `<script[^>]*>`,
})
engine.AddRule(patterns)

result := engine.Check(userInput)
if !result.Passed {
    // handle violation
}
```

### PII Redaction

```go
redactor := pii.NewRedactor(&pii.Config{
    EnabledDetectors:  []pii.Type{pii.TypeEmail, pii.TypePhone, pii.TypeSSN},
    RedactionStrategy: pii.StrategyMask,
    MaskChar:          '*',
})

cleaned, matches := redactor.Redact("Contact john@example.com or 555-123-4567")
// cleaned: "Contact jo**@example.com or ***-***-4567"
```

### Policy Enforcement

```go
enforcer := policy.NewEnforcer()
enforcer.LoadPolicy(&policy.Policy{
    Name:            "admin-only",
    DefaultDecision: policy.DecisionDeny,
    Rules: []policy.Rule{{
        Name: "allow-admins",
        Conditions: []policy.Condition{{
            Field:    "role",
            Operator: policy.OperatorEquals,
            Value:    "admin",
        }},
        Decision: policy.DecisionAllow,
    }},
})

result, _ := enforcer.Evaluate(ctx, "admin-only", &policy.EvaluationContext{
    Fields: map[string]string{"role": "admin"},
})
// result.Decision == policy.DecisionAllow
```

### Composable Content Filtering

```go
chain := content.NewChainFilter(
    content.NewLengthFilter(1, 5000),
    content.NewKeywordFilter([]string{"forbidden"}, false),
)
result, _ := chain.Check(input)
if !result.Allowed {
    fmt.Println("Rejected:", result.Reason)
}
```

### Security Headers Middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("/", handler)

secured := headers.Middleware(headers.DefaultConfig())(mux)
http.ListenAndServe(":8080", secured)
```

### Encrypted Storage

```go
storage := securestorage.NewFileStorage("/var/lib/myapp/secrets")
storage.Store("api_key", "sk-abc123")
value, _ := storage.Retrieve("api_key")
storage.StoreCredentials("database", "admin", "s3cret")
```

## Configuration

Each package uses a Config struct with a `DefaultConfig()` constructor. Pass `nil` to constructors to use defaults. All defaults are production-ready with conservative settings.

## Testing

```bash
go test ./... -count=1 -race    # All tests with race detection
go test ./... -cover             # Coverage report
go vet ./...                     # Vet all packages
```

## Dependencies

- `github.com/stretchr/testify` -- Testing assertions
- No other external dependencies (zero-dependency production code)

## Integration with HelixAgent

The Security module is used throughout HelixAgent:
- Guardrails engine validates LLM input and output in the debate pipeline
- PII redactor cleans sensitive data before logging and storage
- Content filters enforce input constraints on API endpoints
- Policy enforcer controls access to administrative operations
- Scanner interface integrates with Snyk and SonarQube via adapters
- Security headers middleware is applied to all HTTP endpoints
- Secure storage handles API key and credential persistence

The internal adapter at `internal/adapters/security/` bridges these generic types to HelixAgent-specific interfaces.

## License

Proprietary.
