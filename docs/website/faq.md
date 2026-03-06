# FAQ

## Is the PII redactor thread-safe?

Yes. The `pii.Redactor` is immutable after construction. All detectors are stateless (they use compiled regex patterns). Multiple goroutines can call `Redact()` concurrently without synchronization.

## Can I add custom PII detectors?

Yes. Implement the `pii.Detector` interface with a single `Detect(text string) []Match` method and pass your detectors through the config. Custom detectors run alongside the built-in ones (email, phone, SSN, credit card, IP).

## How does the policy enforcement handle conflicting decisions?

When using `EvaluateAll`, the enforcer keeps the most restrictive decision across all policies. The precedence order is: `Deny > Audit > Allow`. If any policy denies the request, the overall result is Deny regardless of other policies allowing it.

## Does the guardrails engine collect all violations or stop at the first?

By default, the engine evaluates all registered rules and collects every violation into `Result.Results`. Set `engine.StopOnFirstFailure = true` to short-circuit on the first rule failure. The short-circuit mode is useful when you only need to know whether content passes, not all the reasons it fails.

## What regex patterns does the ForbiddenPatternsRule support?

The `ForbiddenPatternsRule` accepts standard Go `regexp` syntax. Invalid patterns cause `NewForbiddenPatternsRule()` to return an error at construction time rather than at evaluation time. Use `(?i)` for case-insensitive matching.
