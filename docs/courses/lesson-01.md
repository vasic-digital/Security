# Lesson 1: Content Validation with Guardrails Engine

## Learning Objectives

- Build a content validation engine using the Chain of Responsibility pattern
- Implement thread-safe rule registration with `sync.RWMutex`
- Configure stop-on-first-failure vs. collect-all-violations modes

## Key Concepts

- **Chain of Responsibility**: Rules are evaluated sequentially. By default, all rules run regardless of failures, collecting all violations. When `StopOnFirstFailure` is enabled, the engine short-circuits on the first violation.
- **Rule Interface**: Each rule implements `Name() string` and `Check(content string) error`. Rules are the extension point -- add new validation by implementing this interface.
- **Thread Safety**: `Engine` uses `sync.RWMutex`. `AddRule()` acquires a write lock. `Check()` acquires a read lock, copies the rule slice, then releases before evaluating rules.
- **Severity Levels**: Each rule result includes a severity from the engine configuration, enabling consumers to differentiate between warnings and critical violations.

## Code Walkthrough

### Source: `pkg/guardrails/guardrails.go`

The engine evaluation flow:

1. Engine receives a content string
2. Rules are copied under read lock
3. For each enabled rule, `Check()` is called
4. Results are aggregated into `Result.Results` with severity
5. If any rule fails, `Result.Passed` is false
6. `StopOnFirstFailure` can short-circuit the chain

Built-in rules include `MaxLengthRule`, `ForbiddenPatternsRule`, and `RequireFormatRule`. Custom rules implement the `Rule` interface.

### Source: `pkg/guardrails/guardrails_test.go`

Tests verify rule evaluation, thread-safe concurrent access (10 goroutines x 100 iterations), error aggregation, and stop-on-first-failure behavior.

## Practice Exercise

1. Create an engine with three rules: max length 500 characters, no HTML tags (`<[^>]+>`), and must contain at least one alphanumeric character. Test with various inputs.
2. Write a custom `Rule` that rejects content containing profanity from a configurable word list. Register it with the engine and verify detection.
3. Test concurrent safety: run 10 goroutines simultaneously calling `Check()` while another goroutine calls `AddRule()`. Verify no race conditions occur.
