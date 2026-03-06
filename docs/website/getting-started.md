# Getting Started

## Installation

```bash
go get digital.vasic.security
```

## PII Detection and Redaction

Detect and redact personally identifiable information from text:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/pii"
)

func main() {
    cfg := &pii.Config{
        RedactionStrategy: pii.StrategyMask,
        EnabledDetectors:  []string{"email", "phone", "ssn"},
    }
    redactor := pii.NewRedactor(cfg)

    text := "Contact john@example.com or call 555-123-4567. SSN: 123-45-6789."

    result := redactor.Redact(text)
    fmt.Println(result.RedactedText)
    // "Contact j***@example.com or call ***-***-4567. SSN: ***-**-6789."

    for _, match := range result.Matches {
        fmt.Printf("Found %s: %q at position %d-%d\n",
            match.Type, match.Value, match.Start, match.End)
    }
}
```

## Content Guardrails

Validate content against a set of rules:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/guardrails"
)

func main() {
    engine := guardrails.NewEngine()

    // Add built-in rules
    engine.AddRule(guardrails.NewMaxLengthRule(1000))
    engine.AddRule(guardrails.NewForbiddenPatternsRule([]string{
        `(?i)password\s*[:=]`,
        `(?i)api[_-]?key\s*[:=]`,
    }))

    result := engine.Check("My API_KEY=secret123 is stored here")
    fmt.Printf("Passed: %v\n", result.Passed)       // false
    for _, r := range result.Results {
        if r.Error != "" {
            fmt.Printf("Rule %s failed: %s\n", r.Name, r.Error)
        }
    }
}
```

## Policy Enforcement

Define and evaluate access control policies:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/policy"
)

func main() {
    enforcer := policy.NewEnforcer()

    enforcer.LoadPolicy(&policy.Policy{
        Name:    "admin-access",
        Default: policy.Deny,
        Rules: []policy.Rule{
            {
                Conditions: []policy.Condition{
                    {Field: "role", Operator: policy.Equals, Value: "admin"},
                },
                Decision: policy.Allow,
            },
        },
    })

    // Evaluate against a context
    decision := enforcer.Evaluate("admin-access", map[string]interface{}{
        "role": "admin",
    })
    fmt.Println(decision) // Allow

    decision = enforcer.Evaluate("admin-access", map[string]interface{}{
        "role": "viewer",
    })
    fmt.Println(decision) // Deny
}
```

## Content Filtering

Build a filter chain for content validation:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/content"
)

func main() {
    chain := content.NewChainFilter()

    chain.AddFilter(content.NewLengthFilter(10, 5000))
    chain.AddFilter(content.NewKeywordFilter([]string{"spam", "phishing"}))

    result, err := chain.Check("This is a normal message")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Allowed: %v\n", result.Allowed) // true

    result, _ = chain.Check("Buy spam products now!")
    fmt.Printf("Allowed: %v, Reason: %s\n", result.Allowed, result.Reason) // false
}
```
