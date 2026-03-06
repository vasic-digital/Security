# Lesson 4: Security Headers and Vulnerability Scanning

## Learning Objectives

- Apply security-related HTTP response headers to protect against common web attacks
- Design a vulnerability scanning interface for extensible security auditing
- Combine security primitives into a comprehensive security pipeline

## Key Concepts

- **Security Headers**: The `headers` package sets response headers like `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, and `X-XSS-Protection` to protect against clickjacking, MIME sniffing, and XSS.
- **Scanner Interface**: The `Scanner` interface defines `Scan(target string) ([]Finding, error)`. Concrete scanners (dependency auditors, code analyzers) implement this contract.
- **Report Aggregation**: `RunScanner` wraps scanner errors with the scanner name for context. Multiple scanners can run in sequence, and findings are aggregated into a unified report.

## Code Walkthrough

### Source: `pkg/headers/headers.go`

The headers package provides a function or middleware that sets security headers on every HTTP response. Headers are configurable, with sensible defaults for production use.

### Source: `pkg/scanner/scanner.go`

The scanner package defines:

```go
type Scanner interface {
    Scan(target string) ([]Finding, error)
}

type Finding struct {
    Severity    string
    Title       string
    Description string
    Location    string
}
```

`RunScanner` executes a scanner and wraps any error with the scanner name. The `Report` struct aggregates findings from multiple scanners with severity-based summaries.

### Source: `pkg/scanner/scanner_test.go` and `pkg/headers/headers_test.go`

Tests verify header values, scanner error wrapping, finding aggregation, and report generation.

## Practice Exercise

1. Write an HTTP handler that uses the headers package. Make a request and verify all security headers are present with correct values using a test HTTP client.
2. Implement a `Scanner` that checks Go module dependencies for known vulnerabilities by parsing `go.sum` or running `govulncheck`. Return findings for any issues found.
3. Build a security pipeline that chains guardrails validation, PII redaction, content filtering, and security headers. Test it end-to-end with a sample HTTP request containing PII in the body.
