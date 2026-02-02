package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnforcer_LoadPolicy(t *testing.T) {
	enforcer := NewEnforcer()

	tests := []struct {
		name      string
		policy    *Policy
		expectErr bool
	}{
		{
			"valid policy",
			&Policy{Name: "test", Rules: []Rule{}},
			false,
		},
		{
			"nil policy",
			nil,
			true,
		},
		{
			"empty name",
			&Policy{Name: ""},
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := enforcer.LoadPolicy(tc.policy)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnforcer_LoadPolicies(t *testing.T) {
	enforcer := NewEnforcer()
	policies := []*Policy{
		{Name: "policy1", Rules: []Rule{}},
		{Name: "policy2", Rules: []Rule{}},
	}
	err := enforcer.LoadPolicies(policies)
	require.NoError(t, err)

	assert.NotNil(t, enforcer.GetPolicy("policy1"))
	assert.NotNil(t, enforcer.GetPolicy("policy2"))
}

func TestEnforcer_RemovePolicy(t *testing.T) {
	enforcer := NewEnforcer()
	_ = enforcer.LoadPolicy(&Policy{Name: "test"})
	assert.NotNil(t, enforcer.GetPolicy("test"))

	enforcer.RemovePolicy("test")
	assert.Nil(t, enforcer.GetPolicy("test"))
}

func TestEnforcer_Evaluate_NotFound(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	_, err := enforcer.Evaluate(ctx, "nonexistent",
		&EvaluationContext{Fields: map[string]string{}})
	assert.Error(t, err)
}

func TestEnforcer_Evaluate_Equals(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "test",
		Rules: []Rule{
			{
				Name: "deny_admin",
				Conditions: []Condition{
					{
						Field:    "role",
						Operator: OperatorEquals,
						Value:    "admin",
					},
				},
				Decision: DecisionDeny,
			},
		},
		DefaultDecision: DecisionAllow,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		fields   map[string]string
		expected Decision
	}{
		{
			"admin denied",
			map[string]string{"role": "admin"},
			DecisionDeny,
		},
		{
			"user allowed",
			map[string]string{"role": "user"},
			DecisionAllow,
		},
		{
			"no role field",
			map[string]string{},
			DecisionAllow,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "test",
				&EvaluationContext{Fields: tc.fields})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_Contains(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "content_policy",
		Rules: []Rule{
			{
				Name: "block_injection",
				Conditions: []Condition{
					{
						Field:    "input",
						Operator: OperatorContains,
						Value:    "DROP TABLE",
					},
				},
				Decision: DecisionDeny,
			},
		},
		DefaultDecision: DecisionAllow,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		input    string
		expected Decision
	}{
		{"clean", "hello world", DecisionAllow},
		{"injection", "please DROP TABLE users", DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "content_policy",
				&EvaluationContext{
					Fields: map[string]string{"input": tc.input},
				})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_In(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "role_policy",
		Rules: []Rule{
			{
				Name: "allow_specific_roles",
				Conditions: []Condition{
					{
						Field:    "role",
						Operator: OperatorIn,
						Values:   []string{"admin", "moderator"},
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		role     string
		expected Decision
	}{
		{"admin", "admin", DecisionAllow},
		{"moderator", "moderator", DecisionAllow},
		{"user", "user", DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "role_policy",
				&EvaluationContext{
					Fields: map[string]string{"role": tc.role},
				})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_NotIn(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "blocklist",
		Rules: []Rule{
			{
				Name: "block_specific_ips",
				Conditions: []Condition{
					{
						Field:    "ip",
						Operator: OperatorNotIn,
						Values:   []string{"10.0.0.1", "10.0.0.2"},
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		ip       string
		expected Decision
	}{
		{"allowed IP", "192.168.1.1", DecisionAllow},
		{"blocked IP", "10.0.0.1", DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "blocklist",
				&EvaluationContext{
					Fields: map[string]string{"ip": tc.ip},
				})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_Exists(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "require_auth",
		Rules: []Rule{
			{
				Name: "require_token",
				Conditions: []Condition{
					{
						Field:    "auth_token",
						Operator: OperatorExists,
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		fields   map[string]string
		expected Decision
	}{
		{
			"with token",
			map[string]string{"auth_token": "abc123"},
			DecisionAllow,
		},
		{
			"without token",
			map[string]string{},
			DecisionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "require_auth",
				&EvaluationContext{Fields: tc.fields})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_NotExists(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "no_debug",
		Rules: []Rule{
			{
				Name: "deny_debug_flag",
				Conditions: []Condition{
					{
						Field:    "debug",
						Operator: OperatorNotExists,
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		fields   map[string]string
		expected Decision
	}{
		{"no debug", map[string]string{}, DecisionAllow},
		{"with debug", map[string]string{"debug": "true"}, DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "no_debug",
				&EvaluationContext{Fields: tc.fields})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_StartsWith(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "path_policy",
		Rules: []Rule{
			{
				Name: "allow_api_paths",
				Conditions: []Condition{
					{
						Field:    "path",
						Operator: OperatorStartsWith,
						Value:    "/api/",
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		path     string
		expected Decision
	}{
		{"api path", "/api/users", DecisionAllow},
		{"non-api path", "/admin/users", DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "path_policy",
				&EvaluationContext{
					Fields: map[string]string{"path": tc.path},
				})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_EndsWith(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "extension_policy",
		Rules: []Rule{
			{
				Name: "deny_exe",
				Conditions: []Condition{
					{
						Field:    "filename",
						Operator: OperatorEndsWith,
						Value:    ".exe",
					},
				},
				Decision: DecisionDeny,
			},
		},
		DefaultDecision: DecisionAllow,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		filename string
		expected Decision
	}{
		{"safe file", "doc.pdf", DecisionAllow},
		{"exe file", "malware.exe", DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "extension_policy",
				&EvaluationContext{
					Fields: map[string]string{"filename": tc.filename},
				})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_NotEquals(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "env_policy",
		Rules: []Rule{
			{
				Name: "not_production",
				Conditions: []Condition{
					{
						Field:    "env",
						Operator: OperatorNotEquals,
						Value:    "production",
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		env      string
		expected Decision
	}{
		{"staging", "staging", DecisionAllow},
		{"production", "production", DecisionDeny},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "env_policy",
				&EvaluationContext{
					Fields: map[string]string{"env": tc.env},
				})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_Evaluate_MultipleConditions(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "multi_cond",
		Rules: []Rule{
			{
				Name: "admin_from_internal",
				Conditions: []Condition{
					{
						Field:    "role",
						Operator: OperatorEquals,
						Value:    "admin",
					},
					{
						Field:    "network",
						Operator: OperatorEquals,
						Value:    "internal",
					},
				},
				Decision: DecisionAllow,
			},
		},
		DefaultDecision: DecisionDeny,
	}
	_ = enforcer.LoadPolicy(policy)

	tests := []struct {
		name     string
		fields   map[string]string
		expected Decision
	}{
		{
			"both match",
			map[string]string{
				"role": "admin", "network": "internal",
			},
			DecisionAllow,
		},
		{
			"role matches only",
			map[string]string{
				"role": "admin", "network": "external",
			},
			DecisionDeny,
		},
		{
			"neither matches",
			map[string]string{
				"role": "user", "network": "external",
			},
			DecisionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.Evaluate(ctx, "multi_cond",
				&EvaluationContext{Fields: tc.fields})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_EvaluateAll(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	// Policy 1: allows everything
	_ = enforcer.LoadPolicy(&Policy{
		Name:            "permissive",
		Rules:           []Rule{},
		DefaultDecision: DecisionAllow,
	})

	// Policy 2: denies admin
	_ = enforcer.LoadPolicy(&Policy{
		Name: "restrict_admin",
		Rules: []Rule{
			{
				Name: "deny_admin",
				Conditions: []Condition{
					{
						Field:    "role",
						Operator: OperatorEquals,
						Value:    "admin",
					},
				},
				Decision: DecisionDeny,
			},
		},
		DefaultDecision: DecisionAllow,
	})

	tests := []struct {
		name     string
		fields   map[string]string
		expected Decision
	}{
		{
			"user allowed by all",
			map[string]string{"role": "user"},
			DecisionAllow,
		},
		{
			"admin denied by restrictive",
			map[string]string{"role": "admin"},
			DecisionDeny,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := enforcer.EvaluateAll(ctx,
				&EvaluationContext{Fields: tc.fields})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Decision)
		})
	}
}

func TestEnforcer_EvaluateAll_NoPolicies(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	result, err := enforcer.EvaluateAll(ctx,
		&EvaluationContext{Fields: map[string]string{}})
	require.NoError(t, err)
	assert.Equal(t, DecisionAllow, result.Decision)
}

func TestEnforcer_Evaluate_AuditDecision(t *testing.T) {
	enforcer := NewEnforcer()
	ctx := context.Background()

	policy := &Policy{
		Name: "audit_policy",
		Rules: []Rule{
			{
				Name: "audit_sensitive",
				Conditions: []Condition{
					{
						Field:    "resource",
						Operator: OperatorContains,
						Value:    "sensitive",
					},
				},
				Decision: DecisionAudit,
			},
		},
		DefaultDecision: DecisionAllow,
	}
	_ = enforcer.LoadPolicy(policy)

	result, err := enforcer.Evaluate(ctx, "audit_policy",
		&EvaluationContext{
			Fields: map[string]string{
				"resource": "sensitive-data",
			},
		})
	require.NoError(t, err)
	assert.Equal(t, DecisionAudit, result.Decision)
	assert.NotEmpty(t, result.MatchedRule)
}

func TestEvaluationResult_HasFields(t *testing.T) {
	result := &EvaluationResult{
		Decision:    DecisionDeny,
		MatchedRule: "test_rule",
		Reason:      "matched rule",
	}
	assert.Equal(t, DecisionDeny, result.Decision)
	assert.Equal(t, "test_rule", result.MatchedRule)
	assert.Equal(t, "matched rule", result.Reason)
}
