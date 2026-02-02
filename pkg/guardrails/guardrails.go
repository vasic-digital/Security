// Package guardrails provides a configurable content guardrail engine
// for validating and filtering content against a set of rules.
package guardrails

import (
	"fmt"
	"regexp"
	"sync"
)

// Severity represents the severity level of a rule violation.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rule defines a guardrail rule that can check content.
type Rule interface {
	// Name returns the rule name.
	Name() string
	// Check validates content and returns an error if the rule is violated.
	Check(content string) error
}

// RuleConfig holds configuration for a single rule within the engine.
type RuleConfig struct {
	// Enabled controls whether the rule is active.
	Enabled bool
	// Severity indicates how severe a violation of this rule is.
	Severity Severity
}

// Config configures the guardrail engine.
type Config struct {
	// Rules maps rule names to their configuration.
	Rules map[string]RuleConfig
	// StopOnFirstFailure stops checking after the first rule failure.
	StopOnFirstFailure bool
}

// DefaultConfig returns a Config with all rules enabled at medium severity.
func DefaultConfig() *Config {
	return &Config{
		Rules:              make(map[string]RuleConfig),
		StopOnFirstFailure: false,
	}
}

// RuleResult holds the result of a single rule check.
type RuleResult struct {
	RuleName string   `json:"rule_name"`
	Passed   bool     `json:"passed"`
	Severity Severity `json:"severity"`
	Error    string   `json:"error,omitempty"`
}

// Result holds the aggregate result of all guardrail checks.
type Result struct {
	Passed  bool         `json:"passed"`
	Results []RuleResult `json:"results"`
}

// Engine is the guardrail engine that manages and executes rules.
type Engine struct {
	rules  []Rule
	config *Config
	mu     sync.RWMutex
}

// NewEngine creates a new guardrail Engine with the given config.
func NewEngine(config *Config) *Engine {
	if config == nil {
		config = DefaultConfig()
	}
	return &Engine{
		rules:  make([]Rule, 0),
		config: config,
	}
}

// AddRule adds a rule to the engine.
func (e *Engine) AddRule(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// Check runs all enabled rules against the content and returns the result.
func (e *Engine) Check(content string) *Result {
	e.mu.RLock()
	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	result := &Result{
		Passed:  true,
		Results: make([]RuleResult, 0, len(rules)),
	}

	for _, rule := range rules {
		rc, configured := e.config.Rules[rule.Name()]
		if configured && !rc.Enabled {
			continue
		}

		severity := SeverityMedium
		if configured {
			severity = rc.Severity
		}

		err := rule.Check(content)
		rr := RuleResult{
			RuleName: rule.Name(),
			Passed:   err == nil,
			Severity: severity,
		}
		if err != nil {
			rr.Error = err.Error()
			result.Passed = false
		}
		result.Results = append(result.Results, rr)

		if err != nil && e.config.StopOnFirstFailure {
			break
		}
	}

	return result
}

// MaxLengthRule checks that content does not exceed a maximum length.
type MaxLengthRule struct {
	maxLength int
}

// NewMaxLengthRule creates a new MaxLengthRule with the given limit.
func NewMaxLengthRule(maxLength int) *MaxLengthRule {
	return &MaxLengthRule{maxLength: maxLength}
}

// Name returns the rule name.
func (r *MaxLengthRule) Name() string {
	return "max_length"
}

// Check validates that content length does not exceed the maximum.
func (r *MaxLengthRule) Check(content string) error {
	if len(content) > r.maxLength {
		return fmt.Errorf(
			"content length %d exceeds maximum %d",
			len(content), r.maxLength,
		)
	}
	return nil
}

// ForbiddenPatternsRule checks that content does not match
// any forbidden regular expression patterns.
type ForbiddenPatternsRule struct {
	patterns []*regexp.Regexp
	names    []string
}

// NewForbiddenPatternsRule creates a new ForbiddenPatternsRule.
// The patterns map keys are human-readable names and values are
// regular expression strings.
func NewForbiddenPatternsRule(
	patterns map[string]string,
) (*ForbiddenPatternsRule, error) {
	r := &ForbiddenPatternsRule{
		patterns: make([]*regexp.Regexp, 0, len(patterns)),
		names:    make([]string, 0, len(patterns)),
	}
	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid pattern %q: %w", name, err,
			)
		}
		r.patterns = append(r.patterns, compiled)
		r.names = append(r.names, name)
	}
	return r, nil
}

// Name returns the rule name.
func (r *ForbiddenPatternsRule) Name() string {
	return "forbidden_patterns"
}

// Check validates that content does not match any forbidden pattern.
func (r *ForbiddenPatternsRule) Check(content string) error {
	for i, pattern := range r.patterns {
		if pattern.MatchString(content) {
			return fmt.Errorf(
				"content matches forbidden pattern %q",
				r.names[i],
			)
		}
	}
	return nil
}

// RequireFormatRule checks that content matches a required format.
type RequireFormatRule struct {
	pattern    *regexp.Regexp
	formatName string
}

// NewRequireFormatRule creates a new RequireFormatRule.
func NewRequireFormatRule(
	formatName string, pattern string,
) (*RequireFormatRule, error) {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid format pattern: %w", err)
	}
	return &RequireFormatRule{
		pattern:    compiled,
		formatName: formatName,
	}, nil
}

// Name returns the rule name.
func (r *RequireFormatRule) Name() string {
	return "require_format"
}

// Check validates that content matches the required format.
func (r *RequireFormatRule) Check(content string) error {
	if !r.pattern.MatchString(content) {
		return fmt.Errorf(
			"content does not match required format %q",
			r.formatName,
		)
	}
	return nil
}
