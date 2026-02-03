# User Guide - digital.vasic.security

## Installation

```bash
go get digital.vasic.security
```

Requires Go 1.24 or later.

## Package Overview

| Package | Purpose |
|---------|---------|
| `pkg/guardrails` | Content validation engine with configurable rules |
| `pkg/pii` | PII detection and redaction |
| `pkg/content` | Composable content filter chains |
| `pkg/policy` | Policy enforcement with rules and conditions |
| `pkg/scanner` | Vulnerability scanning interface and reporting |

---

## Guardrails Engine

The guardrails package provides a configurable content validation engine that runs a pipeline of rules against input content.

### Basic Usage

```go
package main

import (
    "fmt"
    "digital.vasic.security/pkg/guardrails"
)

func main() {
    // Create an engine with default config (all rules enabled, medium severity)
    engine := guardrails.NewEngine(nil)

    // Add a max length rule
    engine.AddRule(guardrails.NewMaxLengthRule(1000))

    // Add forbidden patterns (e.g., SQL injection, XSS)
    patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
        "sql_injection": `(?i)(DROP\s+TABLE|DELETE\s+FROM)`,
        "xss":          `(?i)<script`,
    })
    if err != nil {
        panic(err)
    }
    engine.AddRule(patterns)

    // Check content
    result := engine.Check("Hello, this is safe content.")
    fmt.Println("Passed:", result.Passed) // true

    result = engine.Check("DROP TABLE users;")
    fmt.Println("Passed:", result.Passed) // false
    for _, r := range result.Results {
        if !r.Passed {
            fmt.Printf("Rule %q failed (severity: %s): %s\n",
                r.RuleName, r.Severity, r.Error)
        }
    }
}
```

### Configuring Rule Severity and Enabling/Disabling Rules

```go
config := &guardrails.Config{
    Rules: map[string]guardrails.RuleConfig{
        "max_length": {
            Enabled:  true,
            Severity: guardrails.SeverityCritical,
        },
        "forbidden_patterns": {
            Enabled:  true,
            Severity: guardrails.SeverityHigh,
        },
    },
    StopOnFirstFailure: true, // Stop checking after first violation
}

engine := guardrails.NewEngine(config)
```

### Requiring a Content Format

```go
// Require content to be alphanumeric only
formatRule, err := guardrails.NewRequireFormatRule(
    "alphanumeric",
    `^[a-zA-Z0-9\s]+$`,
)
if err != nil {
    panic(err)
}
engine.AddRule(formatRule)
```

### Implementing a Custom Rule

```go
type MinWordCountRule struct {
    minWords int
}

func (r *MinWordCountRule) Name() string {
    return "min_word_count"
}

func (r *MinWordCountRule) Check(content string) error {
    words := strings.Fields(content)
    if len(words) < r.minWords {
        return fmt.Errorf(
            "content has %d words, minimum is %d",
            len(words), r.minWords,
        )
    }
    return nil
}

// Usage:
engine.AddRule(&MinWordCountRule{minWords: 5})
```

### Severity Levels

| Constant | Value |
|----------|-------|
| `SeverityCritical` | `"critical"` |
| `SeverityHigh` | `"high"` |
| `SeverityMedium` | `"medium"` |
| `SeverityLow` | `"low"` |
| `SeverityInfo` | `"info"` |

---

## PII Detection and Redaction

The pii package detects personally identifiable information in text and supports multiple redaction strategies.

### Detecting PII

```go
package main

import (
    "fmt"
    "digital.vasic.security/pkg/pii"
)

func main() {
    redactor := pii.NewRedactor(nil) // default: all detectors, mask strategy

    text := "Contact john@example.com or call 555-123-4567. " +
        "SSN: 123-45-6789, Card: 4111111111111111, Server: 10.0.0.1"

    matches := redactor.Detect(text)
    for _, m := range matches {
        fmt.Printf("Found %s: %q (confidence: %.2f, pos: %d-%d)\n",
            m.Type, m.Value, m.Confidence, m.Start, m.End)
    }
}
```

### Redacting PII with Masking

```go
config := &pii.Config{
    EnabledDetectors:  []pii.Type{pii.TypeEmail, pii.TypePhone},
    RedactionStrategy: pii.StrategyMask,
    MaskChar:          '*',
}
redactor := pii.NewRedactor(config)

text := "Email: user@example.com, Phone: 555-123-4567"
redacted, matches := redactor.Redact(text)
fmt.Println(redacted)
// Output: Email: us**@example.com, Phone: ***-***-4567
fmt.Printf("Redacted %d PII matches\n", len(matches))
```

### Redacting PII with Hashing

```go
config := &pii.Config{
    EnabledDetectors:  []pii.Type{pii.TypeEmail},
    RedactionStrategy: pii.StrategyHash,
    MaskChar:          '*',
}
redactor := pii.NewRedactor(config)

redacted, _ := redactor.Redact("contact user@example.com")
fmt.Println(redacted)
// Output: contact [email:b4c9a289]
```

### Redacting PII with Removal

```go
config := &pii.Config{
    EnabledDetectors:  []pii.Type{pii.TypeSSN, pii.TypeCreditCard},
    RedactionStrategy: pii.StrategyRemove,
    MaskChar:          '*',
}
redactor := pii.NewRedactor(config)

redacted, _ := redactor.Redact("SSN: 123-45-6789")
fmt.Println(redacted)
// Output: SSN: [SSN_REDACTED]
```

### Built-in Detectors

| Detector | PII Type | Confidence | Pattern |
|----------|----------|------------|---------|
| `EmailDetector()` | `email` | 0.90 | RFC-style email addresses |
| `PhoneDetector()` | `phone` | 0.80 | US phone numbers (various formats) |
| `SSNDetector()` | `ssn` | 0.85 | Social Security Numbers (with/without dashes) |
| `CreditCardDetector()` | `credit_card` | 0.70-0.95 | Visa, MasterCard, Amex, Discover (Luhn-validated) |
| `IPAddressDetector()` | `ip_address` | 0.75 | IPv4 addresses |

### Implementing a Custom Detector

```go
type PassportDetector struct{}

func (d *PassportDetector) Detect(text string) []pii.Match {
    pattern := regexp.MustCompile(`\b[A-Z]{2}\d{7}\b`)
    var matches []pii.Match
    for _, loc := range pattern.FindAllStringIndex(text, -1) {
        matches = append(matches, pii.Match{
            Type:       pii.Type("passport"),
            Value:      text[loc[0]:loc[1]],
            Start:      loc[0],
            End:        loc[1],
            Confidence: 0.7,
        })
    }
    return matches
}
```

---

## Content Filtering

The content package provides composable filter chains where content must pass all filters to be accepted.

### Using the Chain Filter

```go
package main

import (
    "fmt"
    "digital.vasic.security/pkg/content"
)

func main() {
    // Create individual filters
    lengthFilter := content.NewLengthFilter(1, 5000)
    keywordFilter := content.NewKeywordFilter(
        []string{"hack", "exploit", "injection"},
        false, // case-insensitive
    )
    patternFilter, err := content.NewPatternFilter(map[string]string{
        "sql_injection": `(?i)(DROP\s+TABLE|DELETE\s+FROM)`,
        "script_tag":   `(?i)<script`,
    })
    if err != nil {
        panic(err)
    }

    // Compose into a chain
    chain := content.NewChainFilter(
        lengthFilter,
        patternFilter,
        keywordFilter,
    )

    // Check content
    result, err := chain.Check("Hello, world!")
    if err != nil {
        panic(err)
    }
    fmt.Println("Allowed:", result.Allowed) // true

    result, _ = chain.Check("DROP TABLE users")
    fmt.Println("Allowed:", result.Allowed) // false
    fmt.Println("Reason:", result.Reason)
}
```

### Adding Filters Dynamically

```go
chain := content.NewChainFilter()
chain.AddFilter(content.NewLengthFilter(10, 0)) // min 10, no max
chain.AddFilter(content.NewKeywordFilter(
    []string{"spam"}, false,
))
```

### Length Filter

```go
// min=1, max=1000: content must be between 1 and 1000 characters
f := content.NewLengthFilter(1, 1000)

// min=0, max=0: no length restrictions (max=0 means unlimited)
f = content.NewLengthFilter(0, 0)
```

### Pattern Filter

```go
// Rejects content matching any provided regex pattern
f, err := content.NewPatternFilter(map[string]string{
    "html_tags":     `<[^>]+>`,
    "sql_keywords":  `(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b`,
})
```

### Keyword Filter

```go
// Case-insensitive (default recommended)
f := content.NewKeywordFilter(
    []string{"forbidden", "blocked", "banned"},
    false,
)

// Case-sensitive
f = content.NewKeywordFilter(
    []string{"CRITICAL", "DANGER"},
    true,
)
```

### Implementing a Custom Filter

```go
type SentimentFilter struct {
    // ... sentiment analysis setup
}

func (f *SentimentFilter) Check(input string) (content.FilterResult, error) {
    score := analyzeSentiment(input) // your logic
    if score < -0.5 {
        return content.FilterResult{
            Allowed: false,
            Reason:  "content has negative sentiment",
            Score:   -score,
        }, nil
    }
    return content.FilterResult{Allowed: true, Score: 0.0}, nil
}
```

---

## Policy Enforcement

The policy package provides a rule-based policy evaluation framework with conditions and decisions.

### Basic Policy Evaluation

```go
package main

import (
    "context"
    "fmt"
    "digital.vasic.security/pkg/policy"
)

func main() {
    enforcer := policy.NewEnforcer()

    // Define a policy
    p := &policy.Policy{
        Name:        "access_control",
        Description: "Controls access based on role and network",
        Rules: []policy.Rule{
            {
                Name: "deny_external_admin",
                Conditions: []policy.Condition{
                    {
                        Field:    "role",
                        Operator: policy.OperatorEquals,
                        Value:    "admin",
                    },
                    {
                        Field:    "network",
                        Operator: policy.OperatorNotEquals,
                        Value:    "internal",
                    },
                },
                Decision: policy.DecisionDeny,
            },
            {
                Name: "audit_sensitive_access",
                Conditions: []policy.Condition{
                    {
                        Field:    "resource",
                        Operator: policy.OperatorContains,
                        Value:    "sensitive",
                    },
                },
                Decision: policy.DecisionAudit,
            },
        },
        DefaultDecision: policy.DecisionAllow,
    }

    if err := enforcer.LoadPolicy(p); err != nil {
        panic(err)
    }

    ctx := context.Background()

    // Evaluate
    result, err := enforcer.Evaluate(ctx, "access_control",
        &policy.EvaluationContext{
            Fields: map[string]string{
                "role":     "admin",
                "network":  "external",
                "resource": "users",
            },
        })
    if err != nil {
        panic(err)
    }
    fmt.Printf("Decision: %s, Rule: %s, Reason: %s\n",
        result.Decision, result.MatchedRule, result.Reason)
    // Decision: deny, Rule: deny_external_admin, ...
}
```

### Evaluating All Policies

The `EvaluateAll` method evaluates all loaded policies and returns the most restrictive decision (Deny > Audit > Allow).

```go
enforcer := policy.NewEnforcer()

_ = enforcer.LoadPolicy(&policy.Policy{
    Name:            "permissive",
    Rules:           []policy.Rule{},
    DefaultDecision: policy.DecisionAllow,
})

_ = enforcer.LoadPolicy(&policy.Policy{
    Name: "restrictive",
    Rules: []policy.Rule{
        {
            Name: "deny_admin",
            Conditions: []policy.Condition{
                {Field: "role", Operator: policy.OperatorEquals, Value: "admin"},
            },
            Decision: policy.DecisionDeny,
        },
    },
    DefaultDecision: policy.DecisionAllow,
})

ctx := context.Background()
result, _ := enforcer.EvaluateAll(ctx, &policy.EvaluationContext{
    Fields: map[string]string{"role": "admin"},
})
// result.Decision == DecisionDeny (most restrictive wins)
```

### Available Operators

| Operator | Description | Fields Used |
|----------|-------------|-------------|
| `OperatorEquals` | Exact string match | `Value` |
| `OperatorNotEquals` | Not equal | `Value` |
| `OperatorContains` | Substring match | `Value` |
| `OperatorStartsWith` | Prefix match | `Value` |
| `OperatorEndsWith` | Suffix match | `Value` |
| `OperatorIn` | Value in list | `Values` |
| `OperatorNotIn` | Value not in list | `Values` |
| `OperatorExists` | Field is present | (none) |
| `OperatorNotExists` | Field is absent | (none) |

### Managing Policies

```go
enforcer := policy.NewEnforcer()

// Load multiple policies at once
err := enforcer.LoadPolicies([]*policy.Policy{p1, p2, p3})

// Retrieve a policy by name
p := enforcer.GetPolicy("access_control")

// Remove a policy
enforcer.RemovePolicy("access_control")
```

---

## Vulnerability Scanning

The scanner package defines a scanning interface and provides report aggregation utilities.

### Implementing a Scanner

```go
package main

import (
    "context"
    "digital.vasic.security/pkg/scanner"
)

type SQLInjectionScanner struct{}

func (s *SQLInjectionScanner) Scan(
    ctx context.Context, target string,
) ([]scanner.Finding, error) {
    var findings []scanner.Finding

    // Your scanning logic here...
    // For example, scan source code files for SQL injection patterns

    findings = append(findings, scanner.Finding{
        Severity:    scanner.SeverityHigh,
        Title:       "Potential SQL Injection",
        Description: "User input concatenated into SQL query",
        Location:    "handlers/user.go:42",
        CWE:         "CWE-89",
        Remediation: "Use parameterized queries or prepared statements",
    })

    return findings, nil
}
```

### Running a Scanner and Getting a Report

```go
ctx := context.Background()
s := &SQLInjectionScanner{}

report, err := scanner.RunScanner(ctx, s, "sql-injection", "/path/to/code")
if err != nil {
    panic(err)
}

fmt.Println(report.Summary())
// Scan Report: 1 findings (Critical: 0, High: 1, Medium: 0, Low: 0, Info: 0)

if report.HasHighOrAbove() {
    fmt.Println("Action required: high-severity findings detected")
}
```

### Filtering Findings by Severity

```go
// Get only high and critical findings
critical := report.FilterBySeverity(scanner.SeverityHigh)
for _, f := range critical {
    fmt.Printf("[%s] %s at %s\n", f.Severity, f.Title, f.Location)
}
```

### Merging Reports from Multiple Scanners

```go
ctx := context.Background()

report1, _ := scanner.RunScanner(ctx, &SQLInjectionScanner{},
    "sql-injection", "/app")
report2, _ := scanner.RunScanner(ctx, &XSSScanner{},
    "xss", "/app")

merged := scanner.MergeReports(report1, report2)
fmt.Println(merged.Summary())
fmt.Println("Scanner:", merged.ScannerName) // "merged"
```

### Report Fields

| Field | Type | Description |
|-------|------|-------------|
| `Findings` | `[]Finding` | All findings from the scan |
| `TotalCount` | `int` | Total number of findings |
| `BySeverity` | `map[Severity]int` | Count by severity level |
| `ScannerName` | `string` | Name of the scanner that produced the report |
| `Target` | `string` | What was scanned |
| `Duration` | `time.Duration` | How long the scan took |
| `ScannedAt` | `time.Time` | When the scan was performed |

---

## Combining Packages

A typical security pipeline combines multiple packages:

```go
func validateInput(input string) error {
    // Step 1: Content filtering
    chain := content.NewChainFilter(
        content.NewLengthFilter(1, 10000),
        content.NewKeywordFilter([]string{"exploit"}, false),
    )
    result, err := chain.Check(input)
    if err != nil {
        return fmt.Errorf("filter error: %w", err)
    }
    if !result.Allowed {
        return fmt.Errorf("content rejected: %s", result.Reason)
    }

    // Step 2: PII redaction
    redactor := pii.NewRedactor(nil)
    sanitized, matches := redactor.Redact(input)
    if len(matches) > 0 {
        log.Printf("Redacted %d PII instances", len(matches))
    }

    // Step 3: Guardrail validation
    engine := guardrails.NewEngine(nil)
    engine.AddRule(guardrails.NewMaxLengthRule(10000))
    fp, _ := guardrails.NewForbiddenPatternsRule(map[string]string{
        "sql": `(?i)DROP\s+TABLE`,
    })
    engine.AddRule(fp)
    gr := engine.Check(sanitized)
    if !gr.Passed {
        return fmt.Errorf("guardrail violation: %s",
            gr.Results[0].Error)
    }

    // Step 4: Policy enforcement
    enforcer := policy.NewEnforcer()
    // ... load policies ...
    ctx := context.Background()
    pr, _ := enforcer.EvaluateAll(ctx, &policy.EvaluationContext{
        Fields: map[string]string{"content": sanitized},
    })
    if pr.Decision == policy.DecisionDeny {
        return fmt.Errorf("policy denied: %s", pr.Reason)
    }

    return nil
}
```
