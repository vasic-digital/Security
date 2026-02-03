# API Reference - digital.vasic.security

## Package guardrails

`import "digital.vasic.security/pkg/guardrails"`

Content guardrail engine with configurable rules, severity levels, and a pipeline for chaining multiple guardrails.

### Types

#### type Severity

```go
type Severity string
```

Represents the severity level of a rule violation.

**Constants:**

```go
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)
```

#### type Rule

```go
type Rule interface {
    Name() string
    Check(content string) error
}
```

Defines a guardrail rule that can check content. `Name()` returns the rule name used for configuration lookup. `Check()` validates content and returns an error if the rule is violated.

#### type RuleConfig

```go
type RuleConfig struct {
    Enabled  bool
    Severity Severity
}
```

Holds configuration for a single rule within the engine. `Enabled` controls whether the rule is active. `Severity` indicates how severe a violation is.

#### type Config

```go
type Config struct {
    Rules              map[string]RuleConfig
    StopOnFirstFailure bool
}
```

Configures the guardrail engine. `Rules` maps rule names (from `Rule.Name()`) to their configuration. `StopOnFirstFailure` stops checking after the first rule failure when true.

#### type RuleResult

```go
type RuleResult struct {
    RuleName string   `json:"rule_name"`
    Passed   bool     `json:"passed"`
    Severity Severity `json:"severity"`
    Error    string   `json:"error,omitempty"`
}
```

Holds the result of a single rule check.

#### type Result

```go
type Result struct {
    Passed  bool         `json:"passed"`
    Results []RuleResult `json:"results"`
}
```

Holds the aggregate result of all guardrail checks. `Passed` is true only if all rules passed.

#### type Engine

```go
type Engine struct {
    // contains unexported fields
}
```

The guardrail engine that manages and executes rules. Thread-safe for concurrent use.

#### type MaxLengthRule

```go
type MaxLengthRule struct {
    // contains unexported fields
}
```

Checks that content does not exceed a maximum length. Rule name: `"max_length"`.

#### type ForbiddenPatternsRule

```go
type ForbiddenPatternsRule struct {
    // contains unexported fields
}
```

Checks that content does not match any forbidden regular expression patterns. Rule name: `"forbidden_patterns"`.

#### type RequireFormatRule

```go
type RequireFormatRule struct {
    // contains unexported fields
}
```

Checks that content matches a required format pattern. Rule name: `"require_format"`.

### Functions

#### func DefaultConfig

```go
func DefaultConfig() *Config
```

Returns a Config with an empty rules map and `StopOnFirstFailure` set to false. Rules not present in the map are treated as enabled with `SeverityMedium`.

#### func NewEngine

```go
func NewEngine(config *Config) *Engine
```

Creates a new guardrail Engine with the given config. If config is nil, `DefaultConfig()` is used.

#### func NewMaxLengthRule

```go
func NewMaxLengthRule(maxLength int) *MaxLengthRule
```

Creates a new MaxLengthRule with the given character limit.

#### func NewForbiddenPatternsRule

```go
func NewForbiddenPatternsRule(patterns map[string]string) (*ForbiddenPatternsRule, error)
```

Creates a new ForbiddenPatternsRule. Map keys are human-readable names and values are regular expression strings. Returns an error if any pattern fails to compile.

#### func NewRequireFormatRule

```go
func NewRequireFormatRule(formatName string, pattern string) (*RequireFormatRule, error)
```

Creates a new RequireFormatRule. `formatName` is a human-readable name for the format. `pattern` is a regular expression that content must match. Returns an error if the pattern fails to compile.

### Methods

#### func (*Engine) AddRule

```go
func (e *Engine) AddRule(rule Rule)
```

Adds a rule to the engine. Thread-safe.

#### func (*Engine) Check

```go
func (e *Engine) Check(content string) *Result
```

Runs all enabled rules against the content and returns the aggregate result. Thread-safe. Rules not configured in `Config.Rules` are treated as enabled with `SeverityMedium`. Rules explicitly disabled in config are skipped.

#### func (*MaxLengthRule) Name

```go
func (r *MaxLengthRule) Name() string
```

Returns `"max_length"`.

#### func (*MaxLengthRule) Check

```go
func (r *MaxLengthRule) Check(content string) error
```

Returns an error if `len(content)` exceeds the configured maximum.

#### func (*ForbiddenPatternsRule) Name

```go
func (r *ForbiddenPatternsRule) Name() string
```

Returns `"forbidden_patterns"`.

#### func (*ForbiddenPatternsRule) Check

```go
func (r *ForbiddenPatternsRule) Check(content string) error
```

Returns an error if content matches any forbidden pattern.

#### func (*RequireFormatRule) Name

```go
func (r *RequireFormatRule) Name() string
```

Returns `"require_format"`.

#### func (*RequireFormatRule) Check

```go
func (r *RequireFormatRule) Check(content string) error
```

Returns an error if content does not match the required format pattern.

---

## Package pii

`import "digital.vasic.security/pkg/pii"`

PII detection and redaction with built-in detectors for email, phone, SSN, credit card, and IP address patterns.

### Types

#### type Type

```go
type Type string
```

Represents a type of personally identifiable information.

**Constants:**

```go
const (
    TypeEmail      Type = "email"
    TypePhone      Type = "phone"
    TypeSSN        Type = "ssn"
    TypeCreditCard Type = "credit_card"
    TypeIPAddress  Type = "ip_address"
)
```

#### type Match

```go
type Match struct {
    Type       Type    `json:"type"`
    Value      string  `json:"value"`
    Start      int     `json:"start"`
    End        int     `json:"end"`
    Confidence float64 `json:"confidence"`
}
```

Represents a detected PII occurrence. `Start` and `End` are byte offsets into the original text. `Confidence` ranges from 0.0 to 1.0.

#### type Detector

```go
type Detector interface {
    Detect(text string) []Match
}
```

Detects PII in text. Returns a slice of all detected PII occurrences.

#### type RedactionStrategy

```go
type RedactionStrategy string
```

Defines how detected PII should be redacted.

**Constants:**

```go
const (
    StrategyMask   RedactionStrategy = "mask"
    StrategyHash   RedactionStrategy = "hash"
    StrategyRemove RedactionStrategy = "remove"
)
```

- **Mask**: Partially masks the value while preserving some identifying information (e.g., email domain, last 4 digits).
- **Hash**: Replaces with a truncated SHA-256 hash in the format `[type:hexhash]`.
- **Remove**: Replaces with `[TYPE_REDACTED]` placeholder.

#### type Config

```go
type Config struct {
    EnabledDetectors  []Type
    RedactionStrategy RedactionStrategy
    MaskChar          rune
}
```

Configures PII detection and redaction. `EnabledDetectors` selects which PII types to scan for. `MaskChar` is the character used for masking (default `'*'`).

#### type Redactor

```go
type Redactor struct {
    // contains unexported fields
}
```

Redacts PII from text using configured detectors and redaction strategy.

### Functions

#### func DefaultConfig

```go
func DefaultConfig() *Config
```

Returns a Config with all 5 detectors enabled, mask redaction strategy, and `'*'` as the mask character.

#### func EmailDetector

```go
func EmailDetector() Detector
```

Returns a Detector for email addresses. Confidence: 0.90.

#### func PhoneDetector

```go
func PhoneDetector() Detector
```

Returns a Detector for US phone numbers (various formats including parentheses, dots, dashes). Confidence: 0.80.

#### func SSNDetector

```go
func SSNDetector() Detector
```

Returns a Detector for Social Security Numbers (with or without dashes). Confidence: 0.85.

#### func CreditCardDetector

```go
func CreditCardDetector() Detector
```

Returns a Detector for credit card numbers (Visa, MasterCard, Amex, Discover). Uses Luhn algorithm validation -- confidence is 0.95 for Luhn-valid numbers, 0.70 otherwise.

#### func IPAddressDetector

```go
func IPAddressDetector() Detector
```

Returns a Detector for IPv4 addresses. Confidence: 0.75.

#### func NewRedactor

```go
func NewRedactor(config *Config) *Redactor
```

Creates a new Redactor with the given config. If config is nil, `DefaultConfig()` is used. Only detectors listed in `EnabledDetectors` are activated.

### Methods

#### func (*Redactor) Detect

```go
func (r *Redactor) Detect(text string) []Match
```

Detects all PII in the given text using enabled detectors. Returns all matches found.

#### func (*Redactor) Redact

```go
func (r *Redactor) Redact(text string) (string, []Match)
```

Detects and redacts PII from text. Returns the redacted text and the matches that were found. If no PII is detected, returns the original text and nil.

---

## Package content

`import "digital.vasic.security/pkg/content"`

Content filtering with composable filter chains. Content must pass all filters in the chain to be allowed.

### Types

#### type FilterResult

```go
type FilterResult struct {
    Allowed bool    `json:"allowed"`
    Reason  string  `json:"reason,omitempty"`
    Score   float64 `json:"score"`
}
```

Contains the result of a content filter check. `Score` represents the severity of the rejection (0.0 for allowed, higher values for more severe rejections).

#### type Filter

```go
type Filter interface {
    Check(input string) (FilterResult, error)
}
```

Checks input content and returns a FilterResult. Returns an error only for infrastructure/internal failures, not for content rejection (which is expressed via `FilterResult.Allowed`).

#### type ChainFilter

```go
type ChainFilter struct {
    // contains unexported fields
}
```

Combines multiple filters. Content must pass all filters to be allowed.

#### type LengthFilter

```go
type LengthFilter struct {
    // contains unexported fields
}
```

Checks that input length is within configured bounds.

#### type PatternFilter

```go
type PatternFilter struct {
    // contains unexported fields
}
```

Rejects content matching any of the forbidden regex patterns.

#### type KeywordFilter

```go
type KeywordFilter struct {
    // contains unexported fields
}
```

Rejects content containing any of the blocked keywords.

### Functions

#### func NewChainFilter

```go
func NewChainFilter(filters ...Filter) *ChainFilter
```

Creates a new ChainFilter with the given filters. Can be called with zero filters (allows all content).

#### func NewLengthFilter

```go
func NewLengthFilter(minLength, maxLength int) *LengthFilter
```

Creates a new LengthFilter. `maxLength` of 0 means no upper limit.

#### func NewPatternFilter

```go
func NewPatternFilter(patterns map[string]string) (*PatternFilter, error)
```

Creates a new PatternFilter. Map keys are descriptive names and values are regular expression strings. Returns an error if any pattern fails to compile.

#### func NewKeywordFilter

```go
func NewKeywordFilter(keywords []string, caseSensitive bool) *KeywordFilter
```

Creates a new KeywordFilter. When `caseSensitive` is false, both keywords and input are lowercased for comparison.

### Methods

#### func (*ChainFilter) AddFilter

```go
func (c *ChainFilter) AddFilter(filter Filter)
```

Adds a filter to the chain.

#### func (*ChainFilter) Check

```go
func (c *ChainFilter) Check(input string) (FilterResult, error)
```

Runs all filters in sequence. Returns the first rejection or an allowing result (with `Score: 0.0`) if all filters pass.

#### func (*LengthFilter) Check

```go
func (f *LengthFilter) Check(input string) (FilterResult, error)
```

Returns a rejection with `Score: 1.0` if input length is outside bounds. Always returns nil error.

#### func (*PatternFilter) Check

```go
func (f *PatternFilter) Check(input string) (FilterResult, error)
```

Returns a rejection with `Score: 0.9` if input matches any forbidden pattern. Always returns nil error.

#### func (*KeywordFilter) Check

```go
func (f *KeywordFilter) Check(input string) (FilterResult, error)
```

Returns a rejection with `Score: 0.8` if input contains any blocked keyword. Always returns nil error.

---

## Package policy

`import "digital.vasic.security/pkg/policy"`

Policy enforcement framework with rules, conditions, operators, and decisions.

### Types

#### type Decision

```go
type Decision string
```

Represents the outcome of a policy evaluation.

**Constants:**

```go
const (
    DecisionAllow Decision = "allow"
    DecisionDeny  Decision = "deny"
    DecisionAudit Decision = "audit"
)
```

Restrictiveness order: `Deny > Audit > Allow`.

#### type Operator

```go
type Operator string
```

Defines how a condition compares values.

**Constants:**

```go
const (
    OperatorEquals     Operator = "equals"
    OperatorNotEquals  Operator = "not_equals"
    OperatorContains   Operator = "contains"
    OperatorStartsWith Operator = "starts_with"
    OperatorEndsWith   Operator = "ends_with"
    OperatorIn         Operator = "in"
    OperatorNotIn      Operator = "not_in"
    OperatorExists     Operator = "exists"
    OperatorNotExists  Operator = "not_exists"
)
```

#### type Condition

```go
type Condition struct {
    Field    string   `json:"field"`
    Operator Operator `json:"operator"`
    Value    string   `json:"value,omitempty"`
    Values   []string `json:"values,omitempty"`
}
```

Defines a single condition within a rule. `Value` is used by single-value operators (Equals, Contains, etc.). `Values` is used by list operators (In, NotIn).

#### type Rule

```go
type Rule struct {
    Name       string      `json:"name"`
    Conditions []Condition `json:"conditions"`
    Decision   Decision    `json:"decision"`
}
```

Defines a policy rule with conditions. All conditions must match (AND logic) for the rule to apply.

#### type Policy

```go
type Policy struct {
    Name            string   `json:"name"`
    Description     string   `json:"description,omitempty"`
    Rules           []Rule   `json:"rules"`
    DefaultDecision Decision `json:"default_decision"`
}
```

A named collection of rules. Rules are evaluated in order; the first matching rule determines the decision. If no rules match, `DefaultDecision` is used.

#### type EvaluationResult

```go
type EvaluationResult struct {
    Decision    Decision `json:"decision"`
    MatchedRule string   `json:"matched_rule,omitempty"`
    Reason      string   `json:"reason,omitempty"`
}
```

Contains the result of evaluating a policy.

#### type EvaluationContext

```go
type EvaluationContext struct {
    Fields map[string]string
}
```

Provides the data for policy evaluation. `Fields` maps field names to values that conditions are evaluated against.

#### type Enforcer

```go
type Enforcer struct {
    // contains unexported fields
}
```

Loads and evaluates policies. Thread-safe for concurrent use.

### Functions

#### func NewEnforcer

```go
func NewEnforcer() *Enforcer
```

Creates a new Enforcer with no policies loaded.

### Methods

#### func (*Enforcer) LoadPolicy

```go
func (e *Enforcer) LoadPolicy(policy *Policy) error
```

Adds a policy to the enforcer. Returns an error if the policy is nil or has an empty name. If a policy with the same name already exists, it is replaced.

#### func (*Enforcer) LoadPolicies

```go
func (e *Enforcer) LoadPolicies(policies []*Policy) error
```

Adds multiple policies to the enforcer. Returns an error wrapping the first policy that fails to load.

#### func (*Enforcer) RemovePolicy

```go
func (e *Enforcer) RemovePolicy(name string)
```

Removes a policy by name. No-op if the policy does not exist.

#### func (*Enforcer) GetPolicy

```go
func (e *Enforcer) GetPolicy(name string) *Policy
```

Returns a policy by name, or nil if not found.

#### func (*Enforcer) Evaluate

```go
func (e *Enforcer) Evaluate(
    ctx context.Context,
    policyName string,
    evalCtx *EvaluationContext,
) (*EvaluationResult, error)
```

Evaluates a specific policy against the given context. Returns an error if the policy is not found.

#### func (*Enforcer) EvaluateAll

```go
func (e *Enforcer) EvaluateAll(
    ctx context.Context,
    evalCtx *EvaluationContext,
) (*EvaluationResult, error)
```

Evaluates all loaded policies against the given context. Returns the most restrictive decision (`Deny > Audit > Allow`). If no policies are loaded, returns `DecisionAllow`.

---

## Package scanner

`import "digital.vasic.security/pkg/scanner"`

Vulnerability scanning interface with severity levels, findings, and aggregated reports.

### Types

#### type Severity

```go
type Severity string
```

Represents the severity level of a finding.

**Constants:**

```go
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)
```

Severity order: Critical (5) > High (4) > Medium (3) > Low (2) > Info (1).

#### type Finding

```go
type Finding struct {
    Severity    Severity `json:"severity"`
    Title       string   `json:"title"`
    Description string   `json:"description"`
    Location    string   `json:"location,omitempty"`
    CWE         string   `json:"cwe,omitempty"`
    Remediation string   `json:"remediation,omitempty"`
}
```

Represents a single vulnerability or issue found by a scanner. `Location` identifies where the issue was found. `CWE` is the Common Weakness Enumeration identifier. `Remediation` provides guidance on how to fix the issue.

#### type Scanner

```go
type Scanner interface {
    Scan(ctx context.Context, target string) ([]Finding, error)
}
```

Scans a target for vulnerabilities. `target` is a scanner-specific identifier (file path, URL, etc.).

#### type Report

```go
type Report struct {
    Findings    []Finding        `json:"findings"`
    TotalCount  int              `json:"total_count"`
    BySeverity  map[Severity]int `json:"by_severity"`
    ScannerName string           `json:"scanner_name,omitempty"`
    Target      string           `json:"target,omitempty"`
    Duration    time.Duration    `json:"duration"`
    ScannedAt   time.Time        `json:"scanned_at"`
}
```

Aggregates findings from one or more scanners.

### Functions

#### func NewReport

```go
func NewReport(
    findings []Finding, scannerName string,
    target string, duration time.Duration,
) *Report
```

Creates a new Report from a set of findings. Automatically computes `TotalCount`, `BySeverity`, and sets `ScannedAt` to the current time.

#### func RunScanner

```go
func RunScanner(
    ctx context.Context, s Scanner,
    scannerName string, target string,
) (*Report, error)
```

Runs a scanner against a target and produces a report. Measures scan duration automatically. Returns an error wrapping the scanner name if the scan fails.

#### func MergeReports

```go
func MergeReports(reports ...*Report) *Report
```

Merges multiple reports into a single report. The merged report has `ScannerName` set to `"merged"`, an empty target, and combined duration. Nil reports in the input are safely skipped.

### Methods

#### func (*Report) HasCritical

```go
func (r *Report) HasCritical() bool
```

Returns true if the report contains any critical-severity findings.

#### func (*Report) HasHighOrAbove

```go
func (r *Report) HasHighOrAbove() bool
```

Returns true if the report contains any high or critical-severity findings.

#### func (*Report) FilterBySeverity

```go
func (r *Report) FilterBySeverity(minSeverity Severity) []Finding
```

Returns findings at or above the given severity level. For example, `FilterBySeverity(SeverityHigh)` returns high and critical findings.

#### func (*Report) Summary

```go
func (r *Report) Summary() string
```

Returns a human-readable summary string in the format: `"Scan Report: N findings (Critical: X, High: Y, Medium: Z, Low: W, Info: V)"`.
