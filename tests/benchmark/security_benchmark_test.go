package benchmark

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"digital.vasic.security/pkg/content"
	"digital.vasic.security/pkg/guardrails"
	"digital.vasic.security/pkg/pii"
	"digital.vasic.security/pkg/policy"
	"digital.vasic.security/pkg/scanner"
	"github.com/stretchr/testify/require"
)

func BenchmarkGuardrailsEngine_Check(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	engine := guardrails.NewEngine(guardrails.DefaultConfig())
	engine.AddRule(guardrails.NewMaxLengthRule(10000))
	patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"script":  `<script`,
		"onclick": `onclick\s*=`,
	})
	require.NoError(b, err)
	engine.AddRule(patterns)

	input := "This is a normal piece of content for benchmarking purposes."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Check(input)
	}
}

func BenchmarkGuardrailsEngine_Check_LargeContent(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	engine := guardrails.NewEngine(guardrails.DefaultConfig())
	engine.AddRule(guardrails.NewMaxLengthRule(100000))
	patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"script": `<script`,
	})
	require.NoError(b, err)
	engine.AddRule(patterns)

	input := strings.Repeat("Normal content. ", 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.Check(input)
	}
}

func BenchmarkPIIRedactor_Detect(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	redactor := pii.NewRedactor(pii.DefaultConfig())
	input := "Contact john@example.com or call (555) 123-4567. " +
		"SSN: 123-45-6789. IP: 10.0.0.1."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = redactor.Detect(input)
	}
}

func BenchmarkPIIRedactor_Redact(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	redactor := pii.NewRedactor(pii.DefaultConfig())
	input := "Contact john@example.com or call (555) 123-4567. " +
		"SSN: 123-45-6789. IP: 10.0.0.1."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = redactor.Redact(input)
	}
}

func BenchmarkContentFilter_ChainCheck(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	chain := content.NewChainFilter(
		content.NewLengthFilter(1, 50000),
		content.NewKeywordFilter([]string{
			"password", "secret", "api_key", "token",
		}, false),
	)
	input := "This is a normal content message without any blocked keywords."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = chain.Check(input)
	}
}

func BenchmarkPolicyEnforcer_Evaluate(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	enforcer := policy.NewEnforcer()
	_ = enforcer.LoadPolicy(&policy.Policy{
		Name: "bench-policy",
		Rules: []policy.Rule{
			{
				Name: "allow-internal",
				Conditions: []policy.Condition{
					{Field: "source", Operator: policy.OperatorEquals, Value: "internal"},
					{Field: "role", Operator: policy.OperatorIn, Values: []string{"admin", "user"}},
				},
				Decision: policy.DecisionAllow,
			},
			{
				Name: "deny-external",
				Conditions: []policy.Condition{
					{Field: "source", Operator: policy.OperatorEquals, Value: "external"},
				},
				Decision: policy.DecisionDeny,
			},
		},
		DefaultDecision: policy.DecisionAudit,
	})
	evalCtx := &policy.EvaluationContext{
		Fields: map[string]string{
			"source": "internal",
			"role":   "user",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enforcer.Evaluate(context.Background(), "bench-policy", evalCtx)
	}
}

func BenchmarkPolicyEnforcer_EvaluateAll(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	enforcer := policy.NewEnforcer()
	for i := 0; i < 10; i++ {
		_ = enforcer.LoadPolicy(&policy.Policy{
			Name: fmt.Sprintf("policy-%d", i),
			Rules: []policy.Rule{
				{
					Name: fmt.Sprintf("rule-%d", i),
					Conditions: []policy.Condition{
						{
							Field:    "key",
							Operator: policy.OperatorEquals,
							Value:    fmt.Sprintf("val-%d", i),
						},
					},
					Decision: policy.DecisionAllow,
				},
			},
			DefaultDecision: policy.DecisionDeny,
		})
	}
	evalCtx := &policy.EvaluationContext{
		Fields: map[string]string{"key": "val-5"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = enforcer.EvaluateAll(context.Background(), evalCtx)
	}
}

func BenchmarkScannerReport_FilterBySeverity(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark test in short mode")
	}

	findings := make([]scanner.Finding, 100)
	severities := []scanner.Severity{
		scanner.SeverityCritical, scanner.SeverityHigh,
		scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityInfo,
	}
	for i := range findings {
		findings[i] = scanner.Finding{
			Severity: severities[i%len(severities)],
			Title:    fmt.Sprintf("Finding %d", i),
		}
	}
	report := scanner.NewReport(findings, "bench", "/app", 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = report.FilterBySeverity(scanner.SeverityMedium)
	}
}
