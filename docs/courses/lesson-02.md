# Lesson 2: PII Detection and Redaction

## Learning Objectives

- Implement a PII redaction system using the Strategy pattern for replacement methods
- Build a Proxy that delegates detection across multiple detector implementations
- Understand the descending-position replacement technique for preserving string offsets

## Key Concepts

- **Strategy Pattern**: The `Redactor` uses a configurable strategy to determine how PII is replaced. Three strategies: `StrategyMask` (partial preservation), `StrategyHash` (SHA-256 tagged hash), `StrategyRemove` (type-labeled placeholder like `[EMAIL_REDACTED]`).
- **Proxy Pattern**: The `Redactor` wraps multiple `Detector` instances. Each detector scans independently, and the Redactor aggregates and applies redaction. This decouples detection from redaction.
- **Descending Position Sort**: Matches are sorted by start position descending before replacement, so replacing from the end preserves earlier match positions.
- **Detector Interface**: `Detect(text string) []Match` -- each detector encapsulates a specific PII pattern (email, phone, SSN).

## Code Walkthrough

### Source: `pkg/pii/pii.go`

The redaction flow:

1. Redactor receives text
2. Each enabled detector scans the full text independently
3. All matches are collected and sorted by start position (descending)
4. Each match is replaced according to the configured strategy
5. Redacted text and original matches are returned

The three strategy implementations in `redactValue()`:
- **Mask**: Preserves partial info (last 4 digits of phone, email domain)
- **Hash**: `[TYPE:SHA256_PREFIX]`
- **Remove**: `[TYPE_REDACTED]`

### Source: `pkg/pii/pii_test.go`

Tests cover each strategy independently, multi-detector aggregation, overlapping matches, and empty input handling.

## Practice Exercise

1. Create a `Redactor` with email and phone detectors using `StrategyMask`. Process the text "Contact john@example.com or 555-123-4567" and verify the output masks appropriately.
2. Compare all three strategies on the same input. Verify that `StrategyHash` produces deterministic output (same input yields same hash).
3. Implement a custom `Detector` for credit card numbers (4 groups of 4 digits). Register it with the Redactor and test with sample text containing both credit cards and emails.
