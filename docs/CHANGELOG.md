# Changelog

All notable changes to the `digital.vasic.security` module are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-03

### Added

- **pkg/guardrails**: Content guardrail engine with configurable rules and severity levels.
  - `Engine` with thread-safe rule management and content checking.
  - `Rule` interface for custom rule implementations.
  - `Config` with per-rule enable/disable, severity configuration, and stop-on-first-failure mode.
  - Built-in rules: `MaxLengthRule`, `ForbiddenPatternsRule`, `RequireFormatRule`.
  - Five severity levels: Critical, High, Medium, Low, Info.

- **pkg/pii**: PII detection and redaction framework.
  - `Detector` interface for custom PII detector implementations.
  - `Redactor` with configurable detector selection and redaction strategies.
  - Built-in detectors: `EmailDetector`, `PhoneDetector`, `SSNDetector`, `CreditCardDetector`, `IPAddressDetector`.
  - Credit card detection with Luhn algorithm validation.
  - Three redaction strategies: Mask (partial preservation), Hash (SHA-256), Remove (placeholder).
  - Type-aware masking that preserves format hints (email domain, last 4 digits).

- **pkg/content**: Content filtering with composable filter chains.
  - `Filter` interface for custom filter implementations.
  - `ChainFilter` for composing multiple filters in sequence (Chain of Responsibility).
  - Built-in filters: `LengthFilter`, `PatternFilter`, `KeywordFilter`.
  - `KeywordFilter` with case-sensitive and case-insensitive modes.

- **pkg/policy**: Policy enforcement framework.
  - `Enforcer` with thread-safe policy management and evaluation.
  - `Policy` with ordered rules and default decision.
  - `Rule` with AND-logic conditions.
  - Nine condition operators: Equals, NotEquals, Contains, StartsWith, EndsWith, In, NotIn, Exists, NotExists.
  - Three decisions: Allow, Deny, Audit.
  - `EvaluateAll` with most-restrictive-wins aggregation (Deny > Audit > Allow).
  - Context propagation via `context.Context`.

- **pkg/scanner**: Vulnerability scanning interface and reporting.
  - `Scanner` interface for custom scanner implementations.
  - `Finding` with severity, title, description, location, CWE, and remediation fields.
  - `Report` with severity breakdown, filtering, summary generation, and timing.
  - `RunScanner` helper for executing scanners with automatic duration measurement.
  - `MergeReports` for combining reports from multiple scanners.
  - `FilterBySeverity` for finding severity-based filtering.

- **Testing**: Comprehensive table-driven test suites for all 5 packages using testify.
- **Documentation**: README, CLAUDE.md, AGENTS.md, user guide, architecture guide, API reference, contributing guide, and Mermaid diagrams.
