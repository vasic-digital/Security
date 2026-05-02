package security

import (
	"testing"
)

func TestScanPrivilegeEscalation(t *testing.T) {
	checks := ScanPrivilegeEscalation()
	if len(checks) == 0 {
		t.Fatal("expected at least one check")
	}

	for _, check := range checks {
		if check.Name == "" {
			t.Error("expected check name to be non-empty")
		}
		if check.Description == "" {
			t.Error("expected check description to be non-empty")
		}
		t.Logf("Check %s: passed=%v details=%s", check.Name, check.Passed, check.Details)
	}
}

func TestCheckWritableRootFS(t *testing.T) {
	check := CheckWritableRootFS()
	if check.Name != "WritableRootFS" {
		t.Errorf("expected WritableRootFS, got %s", check.Name)
	}
	// Result depends on test environment
	_ = check.Passed
}

func TestCheckHostNamespace(t *testing.T) {
	check := CheckHostNamespace()
	if check.Name != "HostNamespace" {
		t.Errorf("expected HostNamespace, got %s", check.Name)
	}
}

func TestCheckSUIDBinaries(t *testing.T) {
	check := CheckSUIDBinaries()
	if check.Name != "SUIDBinaries" {
		t.Errorf("expected SUIDBinaries, got %s", check.Name)
	}
}
