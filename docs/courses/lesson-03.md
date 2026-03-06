# Lesson 3: Content Filters and Policy Enforcement

## Learning Objectives

- Build content filter chains using the Chain of Responsibility pattern
- Implement a policy enforcement engine with condition operators and decision precedence
- Understand the Strategy pattern in condition evaluation

## Key Concepts

- **Content Filter Chain**: `ChainFilter` evaluates filters sequentially. The first filter to reject input short-circuits the chain. Filter types include `LengthFilter`, `PatternFilter`, and `KeywordFilter`.
- **Policy Enforcement**: The `Enforcer` evaluates named policies against a context map. Each policy contains rules with conditions, and conditions use operators (`Equals`, `Contains`, `In`, `GreaterThan`, `LessThan`, etc.).
- **Decision Precedence**: When `EvaluateAll` combines results across policies, it keeps the most restrictive: `Deny > Audit > Allow`.
- **Thread Safety**: `Enforcer` uses `sync.RWMutex`. `LoadPolicy`/`RemovePolicy` acquire write locks; evaluation methods acquire read locks.

## Code Walkthrough

### Source: `pkg/content/content.go`

The `Filter` interface has a single method: `Check(content string) (FilterResult, error)`. The `ChainFilter` iterates through registered filters, returning the first rejection or allowing if all pass.

### Source: `pkg/policy/policy.go`

Policy evaluation flow:

1. Enforcer receives policy name and evaluation context (map of key-value pairs)
2. Policy rules are iterated in order
3. For each rule, all conditions must match (AND logic)
4. The first matching rule determines the decision
5. If no rules match, the policy's default decision is used

Operators are evaluated via the Strategy pattern in `evaluateCondition()`. Each operator constant maps to distinct comparison logic.

### Source: `pkg/content/content_test.go` and `pkg/policy/policy_test.go`

Tests cover filter chain short-circuiting, all operator types, multi-policy evaluation with decision precedence, and concurrent policy access.

## Practice Exercise

1. Build a filter chain with three filters: max 1000 characters, no script tags, no base64-encoded content. Test with inputs that trigger each filter.
2. Define a policy with two rules: "admin_access" allows if role=admin AND department=engineering; "default" denies. Evaluate against various context maps.
3. Create three policies and use `EvaluateAll`. Test that Deny from any policy overrides Allow from others.
