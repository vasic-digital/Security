# CLAUDE.md - Security Module

## Overview

`digital.vasic.security` is a standalone, reusable Go security module providing content guardrails, PII detection and redaction, content filtering, policy enforcement, and vulnerability scanning interfaces.

## Module Structure

- `pkg/guardrails` - Content guardrail engine with configurable rules
- `pkg/pii` - PII detection and redaction (email, phone, SSN, credit card, IP)
- `pkg/content` - Content filtering with chain-of-filters pattern
- `pkg/policy` - Policy enforcement with rules, conditions, and decisions
- `pkg/scanner` - Vulnerability scanning interface with findings and reports

## Build & Test

```bash
go test ./... -count=1 -race    # Run all tests with race detection
go test ./... -cover             # Run with coverage
go vet ./...                     # Vet all packages
```

## Code Style

- Standard Go conventions, `gofmt` formatting
- Imports grouped: stdlib, third-party, internal
- Table-driven tests with testify
- Interfaces: small, focused, accept interfaces return structs
- Errors: always check, wrap with `fmt.Errorf("...: %w", err)`

## Dependencies

- `github.com/stretchr/testify` - Testing assertions
- No other external dependencies
- No dependency on HelixAgent


---

## ⚠️ MANDATORY: NO SUDO OR ROOT EXECUTION

**ALL operations MUST run at local user level ONLY.**

This is a PERMANENT and NON-NEGOTIABLE security constraint:

- **NEVER** use `sudo` in ANY command
- **NEVER** use `su` in ANY command
- **NEVER** execute operations as `root` user
- **NEVER** elevate privileges for file operations
- **ALL** infrastructure commands MUST use user-level container runtimes (rootless podman/docker)
- **ALL** file operations MUST be within user-accessible directories
- **ALL** service management MUST be done via user systemd or local process management
- **ALL** builds, tests, and deployments MUST run as the current user

### Container-Based Solutions
When a build or runtime environment requires system-level dependencies, use containers instead of elevation:

- **Use the `Containers` submodule** (`https://github.com/vasic-digital/Containers`) for containerized build and runtime environments
- **Add the `Containers` submodule as a Git dependency** and configure it for local use within the project
- **Build and run inside containers** to avoid any need for privilege escalation
- **Rootless Podman/Docker** is the preferred container runtime

### Why This Matters
- **Security**: Prevents accidental system-wide damage
- **Reproducibility**: User-level operations are portable across systems
- **Safety**: Limits blast radius of any issues
- **Best Practice**: Modern container workflows are rootless by design

### When You See SUDO
If any script or command suggests using `sudo` or `su`:
1. STOP immediately
2. Find a user-level alternative
3. Use rootless container runtimes
4. Use the `Containers` submodule for containerized builds
5. Modify commands to work within user permissions

**VIOLATION OF THIS CONSTRAINT IS STRICTLY PROHIBITED.**
