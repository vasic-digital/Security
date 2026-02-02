package scanner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockScanner is a test scanner implementation.
type mockScanner struct {
	findings []Finding
	err      error
}

func (m *mockScanner) Scan(
	_ context.Context, _ string,
) ([]Finding, error) {
	return m.findings, m.err
}

func TestNewReport(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Title: "Critical Issue"},
		{Severity: SeverityHigh, Title: "High Issue"},
		{Severity: SeverityMedium, Title: "Medium Issue"},
		{Severity: SeverityLow, Title: "Low Issue"},
		{Severity: SeverityInfo, Title: "Info Issue"},
	}

	report := NewReport(findings, "test-scanner", "/target",
		100*time.Millisecond)

	assert.Equal(t, 5, report.TotalCount)
	assert.Equal(t, 1, report.BySeverity[SeverityCritical])
	assert.Equal(t, 1, report.BySeverity[SeverityHigh])
	assert.Equal(t, 1, report.BySeverity[SeverityMedium])
	assert.Equal(t, 1, report.BySeverity[SeverityLow])
	assert.Equal(t, 1, report.BySeverity[SeverityInfo])
	assert.Equal(t, "test-scanner", report.ScannerName)
	assert.Equal(t, "/target", report.Target)
	assert.False(t, report.ScannedAt.IsZero())
}

func TestReport_HasCritical(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		expected bool
	}{
		{
			"with critical",
			[]Finding{{Severity: SeverityCritical}},
			true,
		},
		{
			"without critical",
			[]Finding{{Severity: SeverityHigh}},
			false,
		},
		{
			"empty",
			[]Finding{},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := NewReport(tc.findings, "", "", 0)
			assert.Equal(t, tc.expected, report.HasCritical())
		})
	}
}

func TestReport_HasHighOrAbove(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		expected bool
	}{
		{
			"with critical",
			[]Finding{{Severity: SeverityCritical}},
			true,
		},
		{
			"with high",
			[]Finding{{Severity: SeverityHigh}},
			true,
		},
		{
			"medium only",
			[]Finding{{Severity: SeverityMedium}},
			false,
		},
		{
			"empty",
			[]Finding{},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := NewReport(tc.findings, "", "", 0)
			assert.Equal(t, tc.expected, report.HasHighOrAbove())
		})
	}
}

func TestReport_FilterBySeverity(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical, Title: "Critical"},
		{Severity: SeverityHigh, Title: "High"},
		{Severity: SeverityMedium, Title: "Medium"},
		{Severity: SeverityLow, Title: "Low"},
		{Severity: SeverityInfo, Title: "Info"},
	}
	report := NewReport(findings, "", "", 0)

	tests := []struct {
		name        string
		minSeverity Severity
		expected    int
	}{
		{"critical only", SeverityCritical, 1},
		{"high and above", SeverityHigh, 2},
		{"medium and above", SeverityMedium, 3},
		{"low and above", SeverityLow, 4},
		{"all", SeverityInfo, 5},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filtered := report.FilterBySeverity(tc.minSeverity)
			assert.Len(t, filtered, tc.expected)
		})
	}
}

func TestReport_Summary(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityCritical},
		{Severity: SeverityHigh},
		{Severity: SeverityHigh},
	}
	report := NewReport(findings, "", "", 0)

	summary := report.Summary()
	assert.Contains(t, summary, "3 findings")
	assert.Contains(t, summary, "Critical: 1")
	assert.Contains(t, summary, "High: 2")
}

func TestRunScanner_Success(t *testing.T) {
	ctx := context.Background()
	s := &mockScanner{
		findings: []Finding{
			{Severity: SeverityHigh, Title: "Test Finding"},
		},
	}

	report, err := RunScanner(ctx, s, "mock", "/target")
	require.NoError(t, err)
	assert.Equal(t, 1, report.TotalCount)
	assert.Equal(t, "mock", report.ScannerName)
	assert.Equal(t, "/target", report.Target)
	assert.Greater(t, report.Duration, time.Duration(0)-1)
}

func TestRunScanner_Error(t *testing.T) {
	ctx := context.Background()
	s := &mockScanner{
		err: fmt.Errorf("scan failed"),
	}

	_, err := RunScanner(ctx, s, "mock", "/target")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan failed")
}

func TestMergeReports(t *testing.T) {
	report1 := NewReport(
		[]Finding{
			{Severity: SeverityCritical, Title: "R1F1"},
		},
		"scanner1", "/target1", 50*time.Millisecond,
	)
	report2 := NewReport(
		[]Finding{
			{Severity: SeverityHigh, Title: "R2F1"},
			{Severity: SeverityLow, Title: "R2F2"},
		},
		"scanner2", "/target2", 100*time.Millisecond,
	)

	merged := MergeReports(report1, report2)
	assert.Equal(t, 3, merged.TotalCount)
	assert.Equal(t, 1, merged.BySeverity[SeverityCritical])
	assert.Equal(t, 1, merged.BySeverity[SeverityHigh])
	assert.Equal(t, 1, merged.BySeverity[SeverityLow])
	assert.Equal(t, "merged", merged.ScannerName)
}

func TestMergeReports_WithNil(t *testing.T) {
	report1 := NewReport(
		[]Finding{{Severity: SeverityHigh}},
		"s1", "", 0,
	)

	merged := MergeReports(report1, nil)
	assert.Equal(t, 1, merged.TotalCount)
}

func TestMergeReports_Empty(t *testing.T) {
	merged := MergeReports()
	assert.Equal(t, 0, merged.TotalCount)
}

func TestFinding_Fields(t *testing.T) {
	f := Finding{
		Severity:    SeverityCritical,
		Title:       "SQL Injection",
		Description: "User input is not sanitized",
		Location:    "app.go:42",
		CWE:         "CWE-89",
		Remediation: "Use parameterized queries",
	}

	assert.Equal(t, SeverityCritical, f.Severity)
	assert.Equal(t, "SQL Injection", f.Title)
	assert.Equal(t, "User input is not sanitized", f.Description)
	assert.Equal(t, "app.go:42", f.Location)
	assert.Equal(t, "CWE-89", f.CWE)
	assert.Equal(t, "Use parameterized queries", f.Remediation)
}

func TestSeverityOrder(t *testing.T) {
	tests := []struct {
		severity Severity
		expected int
	}{
		{SeverityCritical, 5},
		{SeverityHigh, 4},
		{SeverityMedium, 3},
		{SeverityLow, 2},
		{SeverityInfo, 1},
		{Severity("unknown"), 0},
	}

	for _, tc := range tests {
		t.Run(string(tc.severity), func(t *testing.T) {
			assert.Equal(t, tc.expected, severityOrder(tc.severity))
		})
	}
}

func TestReport_EmptyFindings(t *testing.T) {
	report := NewReport([]Finding{}, "scanner", "/target", 0)
	assert.Equal(t, 0, report.TotalCount)
	assert.False(t, report.HasCritical())
	assert.False(t, report.HasHighOrAbove())
	assert.Nil(t, report.FilterBySeverity(SeverityInfo))
}
