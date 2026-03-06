# Examples

## PII Redaction Strategies

Compare the three available redaction strategies:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/pii"
)

func main() {
    text := "Email: alice@example.com, Phone: 555-123-4567"

    // Strategy 1: Mask -- preserves partial identifying info
    maskRedactor := pii.NewRedactor(&pii.Config{
        RedactionStrategy: pii.StrategyMask,
    })
    fmt.Println(maskRedactor.Redact(text).RedactedText)
    // "Email: a***@example.com, Phone: ***-***-4567"

    // Strategy 2: Hash -- replaces with truncated SHA-256
    hashRedactor := pii.NewRedactor(&pii.Config{
        RedactionStrategy: pii.StrategyHash,
    })
    fmt.Println(hashRedactor.Redact(text).RedactedText)
    // "Email: [EMAIL:a1b2c3d4], Phone: [PHONE:e5f6g7h8]"

    // Strategy 3: Remove -- replaces with type-labeled placeholder
    removeRedactor := pii.NewRedactor(&pii.Config{
        RedactionStrategy: pii.StrategyRemove,
    })
    fmt.Println(removeRedactor.Redact(text).RedactedText)
    // "Email: [EMAIL_REDACTED], Phone: [PHONE_REDACTED]"
}
```

## Multi-Policy Evaluation

Evaluate input against multiple policies and use the most restrictive decision:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/policy"
)

func main() {
    enforcer := policy.NewEnforcer()

    // Geographic restriction policy
    enforcer.LoadPolicy(&policy.Policy{
        Name:    "geo-restriction",
        Default: policy.Allow,
        Rules: []policy.Rule{
            {
                Conditions: []policy.Condition{
                    {Field: "country", Operator: policy.In, Value: []string{"US", "CA", "GB"}},
                },
                Decision: policy.Allow,
            },
            {
                Conditions: []policy.Condition{
                    {Field: "country", Operator: policy.NotIn, Value: []string{"US", "CA", "GB"}},
                },
                Decision: policy.Deny,
            },
        },
    })

    // Rate tier policy
    enforcer.LoadPolicy(&policy.Policy{
        Name:    "rate-tier",
        Default: policy.Allow,
        Rules: []policy.Rule{
            {
                Conditions: []policy.Condition{
                    {Field: "tier", Operator: policy.Equals, Value: "free"},
                    {Field: "requests_today", Operator: policy.GreaterThan, Value: 100},
                },
                Decision: policy.Deny,
            },
        },
    })

    // EvaluateAll returns the most restrictive decision across all policies
    ctx := map[string]interface{}{
        "country":        "US",
        "tier":           "free",
        "requests_today": 150,
    }

    decision := enforcer.EvaluateAll(ctx)
    fmt.Println(decision) // Deny (rate-tier denies, even though geo allows)
}
```

## Guardrails Engine with Stop-on-First-Failure

Configure the engine to short-circuit on the first rule violation:

```go
package main

import (
    "fmt"

    "digital.vasic.security/pkg/guardrails"
)

func main() {
    engine := guardrails.NewEngine()
    engine.StopOnFirstFailure = true

    engine.AddRule(guardrails.NewMaxLengthRule(500))
    engine.AddRule(guardrails.NewRequireFormatRule("title", `^[A-Z]`))
    engine.AddRule(guardrails.NewForbiddenPatternsRule([]string{`<script`}))

    // This fails the max-length rule and stops immediately
    longContent := make([]byte, 600)
    for i := range longContent {
        longContent[i] = 'x'
    }
    result := engine.Check(string(longContent))

    fmt.Printf("Passed: %v\n", result.Passed)
    fmt.Printf("Rules evaluated: %d\n", len(result.Results)) // 1 (stopped early)
}
```
