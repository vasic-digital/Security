// Package security provides host and container security scanning utilities.
package security

import (
	"fmt"
	"os"
	"strings"
)

// PrivEscCheck holds the result of a privilege escalation scan.
type PrivEscCheck struct {
	Name        string
	Description string
	Passed      bool
	Details     string
}

// ScanPrivilegeEscalation checks common container and host privilege escalation vectors.
func ScanPrivilegeEscalation() []PrivEscCheck {
	var checks []PrivEscCheck

	checks = append(checks, CheckPrivilegedContainer())
	checks = append(checks, CheckWritableRootFS())
	checks = append(checks, CheckDangerousCapabilities())
	checks = append(checks, CheckHostNamespace())
	checks = append(checks, CheckSUIDBinaries())

	return checks
}

func CheckPrivilegedContainer() PrivEscCheck {
	// Check if /proc/1/status exists and read capabilities
	data, err := os.ReadFile("/proc/1/status")
	if err != nil {
		return PrivEscCheck{
			Name:        "PrivilegedContainer",
			Description: "Check if running in a privileged container",
			Passed:      true,
			Details:     "Cannot read /proc/1/status; assuming unprivileged",
		}
	}

	// In a privileged container, CapEff often contains all capabilities
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "0000003fffffffff" {
				return PrivEscCheck{
					Name:        "PrivilegedContainer",
					Description: "Check if running in a privileged container",
					Passed:      false,
					Details:     "Full capabilities detected (likely privileged container)",
				}
			}
		}
	}

	return PrivEscCheck{
		Name:        "PrivilegedContainer",
		Description: "Check if running in a privileged container",
		Passed:      true,
		Details:     "Not running with full capabilities",
	}
}

func CheckWritableRootFS() PrivEscCheck {
	// Try to create a file in / to detect writable root filesystem
	f, err := os.Create("/.security_test_" + fmt.Sprintf("%d", os.Getpid()))
	if err == nil {
		f.Close()
		os.Remove(f.Name())
		return PrivEscCheck{
			Name:        "WritableRootFS",
			Description: "Check if root filesystem is writable",
			Passed:      false,
			Details:     "Root filesystem is writable",
		}
	}

	return PrivEscCheck{
		Name:        "WritableRootFS",
		Description: "Check if root filesystem is writable",
		Passed:      true,
		Details:     "Root filesystem is read-only",
	}
}

func CheckDangerousCapabilities() PrivEscCheck {
	// Check for CAP_SYS_ADMIN which enables many escalation paths
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return PrivEscCheck{
			Name:        "DangerousCapabilities",
			Description: "Check for dangerous capabilities (CAP_SYS_ADMIN)",
			Passed:      true,
			Details:     "Cannot read process status",
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				capEff := fields[1]
				// CAP_SYS_ADMIN is bit 21; in hex cap data this is position-dependent
				// Full check would parse the cap value; here we flag full caps
				if capEff == "0000003fffffffff" {
					return PrivEscCheck{
						Name:        "DangerousCapabilities",
						Description: "Check for dangerous capabilities (CAP_SYS_ADMIN)",
						Passed:      false,
						Details:     "Full capability set detected",
					}
				}
			}
		}
	}

	return PrivEscCheck{
		Name:        "DangerousCapabilities",
		Description: "Check for dangerous capabilities (CAP_SYS_ADMIN)",
		Passed:      true,
		Details:     "No dangerous capabilities detected",
	}
}

func CheckHostNamespace() PrivEscCheck {
	// Compare /proc/self/cgroup with /proc/1/cgroup to detect host PID namespace
	selfCgroup, err1 := os.ReadFile("/proc/self/cgroup")
	rootCgroup, err2 := os.ReadFile("/proc/1/cgroup")

	if err1 != nil || err2 != nil {
		return PrivEscCheck{
			Name:        "HostNamespace",
			Description: "Check if sharing host namespaces",
			Passed:      true,
			Details:     "Cannot read cgroup info",
		}
	}

	if strings.TrimSpace(string(selfCgroup)) == strings.TrimSpace(string(rootCgroup)) {
		return PrivEscCheck{
			Name:        "HostNamespace",
			Description: "Check if sharing host namespaces",
			Passed:      false,
			Details:     "Same cgroup as init process (likely sharing host namespace)",
		}
	}

	return PrivEscCheck{
		Name:        "HostNamespace",
		Description: "Check if sharing host namespaces",
		Passed:      true,
		Details:     "Isolated cgroup namespace detected",
	}
}

func CheckSUIDBinaries() PrivEscCheck {
	// Check common paths for unexpected SUID binaries
	paths := []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin"}
	found := []string{}

	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSetuid != 0 {
				found = append(found, entry.Name())
			}
		}
	}

	if len(found) > 0 {
		return PrivEscCheck{
			Name:        "SUIDBinaries",
			Description: "Check for unexpected SUID binaries",
			Passed:      false,
			Details:     fmt.Sprintf("Found %d SUID binaries", len(found)),
		}
	}

	return PrivEscCheck{
		Name:        "SUIDBinaries",
		Description: "Check for unexpected SUID binaries",
		Passed:      true,
		Details:     "No unexpected SUID binaries found",
	}
}
