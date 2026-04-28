# AGENTS.md - Security Module Multi-Agent Coordination Guide

## Module Overview

`digital.vasic.security` is a standalone, reusable Go security module (Go 1.24+) providing five independent packages for content guardrails, PII detection and redaction, content filtering, policy enforcement, and vulnerability scanning. The module has zero dependencies on HelixAgent and only depends on `github.com/stretchr/testify` for testing.

## Package Responsibilities

### pkg/guardrails
- **Owner**: Content Safety Agent
- **Responsibility**: Configurable content guardrail engine with rule-based validation.
- **Key types**: `Engine`, `Rule` (interface), `Config`, `RuleConfig`, `Result`, `RuleResult`, `Severity`
- **Built-in rules**: `MaxLengthRule`, `ForbiddenPatternsRule`, `RequireFormatRule`
- **Concurrency**: Thread-safe via `sync.RWMutex` on `Engine`
- **Key file**: `pkg/guardrails/guardrails.go`

### pkg/pii
- **Owner**: Data Privacy Agent
- **Responsibility**: PII detection and redaction with configurable detectors and redaction strategies.
- **Key types**: `Redactor`, `Detector` (interface), `Config`, `Match`, `Type`, `RedactionStrategy`
- **Built-in detectors**: `EmailDetector`, `PhoneDetector`, `SSNDetector`, `CreditCardDetector`, `IPAddressDetector`
- **Redaction strategies**: `StrategyMask`, `StrategyHash`, `StrategyRemove`
- **Validation**: Luhn algorithm for credit card number verification
- **Key file**: `pkg/pii/pii.go`

### pkg/content
- **Owner**: Content Filtering Agent
- **Responsibility**: Composable content filter chains for input validation.
- **Key types**: `ChainFilter`, `Filter` (interface), `FilterResult`, `LengthFilter`, `PatternFilter`, `KeywordFilter`
- **Pattern**: Chain of Responsibility -- content must pass all filters sequentially.
- **Key file**: `pkg/content/content.go`

### pkg/policy
- **Owner**: Policy Enforcement Agent
- **Responsibility**: Rule-based policy evaluation with conditions, operators, and decisions.
- **Key types**: `Enforcer`, `Policy`, `Rule`, `Condition`, `EvaluationContext`, `EvaluationResult`, `Decision`, `Operator`
- **Decisions**: `Allow`, `Deny`, `Audit`
- **Operators**: `Equals`, `NotEquals`, `Contains`, `StartsWith`, `EndsWith`, `In`, `NotIn`, `Exists`, `NotExists`
- **Concurrency**: Thread-safe via `sync.RWMutex` on `Enforcer`
- **Context support**: All evaluation methods accept `context.Context`
- **Key file**: `pkg/policy/policy.go`

### pkg/scanner
- **Owner**: Vulnerability Scanning Agent
- **Responsibility**: Vulnerability scanning interface with findings aggregation and reporting.
- **Key types**: `Scanner` (interface), `Finding`, `Report`, `Severity`
- **Report features**: Severity breakdown, filtering, merging, summary generation
- **Context support**: `Scanner.Scan` accepts `context.Context`
- **Key file**: `pkg/scanner/scanner.go`

## Agent Coordination Model

### Independence Principle
Each package is fully self-contained with no cross-package imports. Agents working on different packages can operate in complete isolation without coordination overhead.

### Integration Points
When an integrating application (such as HelixAgent) combines these packages, coordination follows this order:

1. **Content Filtering** (`content`) -- first-pass validation of raw input (length, patterns, keywords)
2. **PII Detection** (`pii`) -- detect and redact sensitive data before further processing
3. **Guardrails** (`guardrails`) -- validate processed content against domain-specific rules
4. **Policy Enforcement** (`policy`) -- evaluate access control and behavioral policies
5. **Vulnerability Scanning** (`scanner`) -- scan artifacts for security vulnerabilities

### Work Distribution Guidelines
- **Adding a new built-in rule/filter/detector**: Work within the single relevant package. No cross-package changes needed.
- **Adding a new package**: Create under `pkg/`, ensure zero imports from other `pkg/` packages, add tests.
- **Modifying an interface**: Coordinate with all agents that may implement or consume that interface. The interfaces are `Rule`, `Detector`, `Filter`, `Scanner`.
- **Updating shared patterns** (e.g., severity levels): Both `guardrails` and `scanner` define their own `Severity` type independently. Changes to one do not affect the other.

## Key Files

| File | Purpose |
|------|---------|
| `go.mod` | Module definition (`digital.vasic.security`, Go 1.24) |
| `CLAUDE.md` | AI assistant instructions |
| `README.md` | Project overview |
| `pkg/guardrails/guardrails.go` | Guardrail engine, rules, config |
| `pkg/guardrails/guardrails_test.go` | Guardrail tests (11 test functions) |
| `pkg/pii/pii.go` | PII detection, redaction, detectors |
| `pkg/pii/pii_test.go` | PII tests (16 test functions) |
| `pkg/content/content.go` | Content filters and chain |
| `pkg/content/content_test.go` | Content filter tests (10 test functions) |
| `pkg/policy/policy.go` | Policy enforcer, rules, conditions |
| `pkg/policy/policy_test.go` | Policy tests (15 test functions) |
| `pkg/scanner/scanner.go` | Scanner interface, report, findings |
| `pkg/scanner/scanner_test.go` | Scanner tests (12 test functions) |

## Test Commands

```bash
# Run all tests with race detection
go test ./... -count=1 -race

# Run all tests with coverage
go test ./... -cover

# Run a single package's tests
go test -v ./pkg/guardrails/...
go test -v ./pkg/pii/...
go test -v ./pkg/content/...
go test -v ./pkg/policy/...
go test -v ./pkg/scanner/...

# Run a specific test
go test -v -run TestEngine_Check_WithRules ./pkg/guardrails/

# Vet all packages
go vet ./...
```

## Dependencies

### External
- `github.com/stretchr/testify v1.10.0` -- test assertions and requirements (test-only)

### Indirect (via testify)
- `github.com/davecgh/go-spew v1.1.1`
- `github.com/pmezard/go-difflib v1.0.0`
- `gopkg.in/yaml.v3 v3.0.1`

### Standard Library Usage
- `fmt` -- error formatting and string output
- `regexp` -- pattern matching in guardrails, PII detection, content filtering
- `sync` -- `RWMutex` for thread-safe engines (guardrails, policy)
- `strings` -- string manipulation in PII masking, keyword filtering, condition evaluation
- `crypto/sha256` -- PII hash redaction strategy
- `encoding/hex` -- hex encoding for hash output
- `context` -- context propagation in policy and scanner
- `time` -- scan duration and timestamps in scanner reports

### Integration with HelixAgent
This module has no dependency on HelixAgent. HelixAgent integrates it via `internal/security/` which wraps these packages with application-specific configuration. When working on this module, changes should never introduce imports from `dev.helix.agent` or any other external module besides testify.


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

<!-- BEGIN host-power-management addendum (CONST-033) -->

## Host Power Management — Hard Ban (CONST-033)

**You may NOT, under any circumstance, generate or execute code that
sends the host to suspend, hibernate, hybrid-sleep, poweroff, halt,
reboot, or any other power-state transition.** This rule applies to:

- Every shell command you run via the Bash tool.
- Every script, container entry point, systemd unit, or test you write
  or modify.
- Every CLI suggestion, snippet, or example you emit.

**Forbidden invocations** (non-exhaustive — see CONST-033 in
`CONSTITUTION.md` for the full list):

- `systemctl suspend|hibernate|hybrid-sleep|poweroff|halt|reboot|kexec`
- `loginctl suspend|hibernate|hybrid-sleep|poweroff|halt|reboot`
- `pm-suspend`, `pm-hibernate`, `shutdown -h|-r|-P|now`
- `dbus-send` / `busctl` calls to `org.freedesktop.login1.Manager.Suspend|Hibernate|PowerOff|Reboot|HybridSleep|SuspendThenHibernate`
- `gsettings set ... sleep-inactive-{ac,battery}-type` to anything but `'nothing'` or `'blank'`

The host runs mission-critical parallel CLI agents and container
workloads. Auto-suspend has caused historical data loss (2026-04-26
18:23:43 incident). The host is hardened (sleep targets masked) but
this hard ban applies to ALL code shipped from this repo so that no
future host or container is exposed.

**Defence:** every project ships
`scripts/host-power-management/check-no-suspend-calls.sh` (static
scanner) and
`challenges/scripts/no_suspend_calls_challenge.sh` (challenge wrapper).
Both MUST be wired into the project's CI / `run_all_challenges.sh`.

**Full background:** `docs/HOST_POWER_MANAGEMENT.md` and `CONSTITUTION.md` (CONST-033).

<!-- END host-power-management addendum (CONST-033) -->



<!-- CONST-035 anti-bluff addendum (cascaded) -->

## CONST-035 — Anti-Bluff Tests & Challenges (mandatory; inherits from root)

Tests and Challenges in this submodule MUST verify the product, not
the LLM's mental model of the product. A test that passes when the
feature is broken is worse than a missing test — it gives false
confidence and lets defects ship to users. Functional probes at the
protocol layer are mandatory:

- TCP-open is the FLOOR, not the ceiling. Postgres → execute
  `SELECT 1`. Redis → `PING` returns `PONG`. ChromaDB → `GET
  /api/v1/heartbeat` returns 200. MCP server → TCP connect + valid
  JSON-RPC handshake. HTTP gateway → real request, real response,
  non-empty body.
- Container `Up` is NOT application healthy. A `docker/podman ps`
  `Up` status only means PID 1 is running; the application may be
  crash-looping internally.
- No mocks/fakes outside unit tests (already CONST-030; CONST-035
  raises the cost of a mock-driven false pass to the same severity
  as a regression).
- Re-verify after every change. Don't assume a previously-passing
  test still verifies the same scope after a refactor.
- Verification of CONST-035 itself: deliberately break the feature
  (e.g. `kill <service>`, swap a password). The test MUST fail. If
  it still passes, the test is non-conformant and MUST be tightened.

## CONST-033 clarification — distinguishing host events from sluggishness

Heavy container builds (BuildKit pulling many GB of layers, parallel
podman/docker compose-up across many services) can make the host
**appear** unresponsive — high load average, slow SSH, watchers
timing out. **This is NOT a CONST-033 violation.** Suspend / hibernate
/ logout are categorically different events. Distinguish via:

- `uptime` — recent boot? if so, the host actually rebooted.
- `loginctl list-sessions` — session(s) still active? if yes, no logout.
- `journalctl ... | grep -i 'will suspend\|hibernate'` — zero broadcasts
  since the CONST-033 fix means no suspend ever happened.
- `dmesg | grep -i 'killed process\|out of memory'` — OOM kills are
  also NOT host-power events; they're memory-pressure-induced and
  require their own separate fix (lower per-container memory limits,
  reduce parallelism).

A sluggish host under build pressure recovers when the build finishes;
a suspended host requires explicit unsuspend (and CONST-033 should
make that impossible by hardening `IdleAction=ignore` +
`HandleSuspendKey=ignore` + masked `sleep.target`,
`suspend.target`, `hibernate.target`, `hybrid-sleep.target`).

If you observe what looks like a suspend during heavy builds, the
correct first action is **not** "edit CONST-033" but `bash
challenges/scripts/host_no_auto_suspend_challenge.sh` to confirm the
hardening is intact. If hardening is intact AND no suspend
broadcast appears in journal, the perceived event was build-pressure
sluggishness, not a power transition.

<!-- BEGIN no-session-termination addendum (CONST-036) -->

## User-Session Termination — Hard Ban (CONST-036)

**You may NOT, under any circumstance, generate or execute code that
ends the currently-logged-in user's desktop session, kills their
`user@<UID>.service` user manager, or indirectly forces them to
manually log out / power off.** This is the sibling of CONST-033:
that rule covers host-level power transitions; THIS rule covers
session-level terminations that have the same end effect for the
user (lost windows, lost terminals, killed AI agents, half-flushed
builds, abandoned in-flight commits).

**Why this rule exists.** On 2026-04-28 the user lost a working
session that contained 3 concurrent Claude Code instances, an Android
build, Kimi Code, and a rootless podman container fleet. The
`user.slice` consumed 60.6 GiB peak / 5.2 GiB swap, the GUI became
unresponsive, the user was forced to log out and then power off via
the GNOME shell. The host could not auto-suspend (CONST-033 was in
place and verified) and the kernel OOM killer never fired — but the
user had to manually end the session anyway, because nothing
prevented overlapping heavy workloads from saturating the slice.
CONST-036 closes that loophole at both the source-code layer and the
operational layer. See
`docs/issues/fixed/SESSION_LOSS_2026-04-28.md` in the HelixAgent
project.

**Forbidden direct invocations** (non-exhaustive):

- `loginctl terminate-user|terminate-session|kill-user|kill-session`
- `systemctl stop user@<UID>` / `systemctl kill user@<UID>`
- `gnome-session-quit`
- `pkill -KILL -u $USER` / `killall -u $USER`
- `dbus-send` / `busctl` calls to `org.gnome.SessionManager.Logout|Shutdown|Reboot`
- `echo X > /sys/power/state`
- `/usr/bin/poweroff`, `/usr/bin/reboot`, `/usr/bin/halt`

**Indirect-pressure clauses:**

1. Do not spawn parallel heavy workloads casually; check `free -h`
   first; keep `user.slice` under 70% of physical RAM.
2. Long-lived background subagents go in `system.slice`. Rootless
   podman containers die with the user manager.
3. Document AI-agent concurrency caps in CLAUDE.md.
4. Never script "log out and back in" recovery flows.

**Defence:** every project ships
`scripts/host-power-management/check-no-session-termination-calls.sh`
(static scanner) and
`challenges/scripts/no_session_termination_calls_challenge.sh`
(challenge wrapper). Both MUST be wired into the project's CI /
`run_all_challenges.sh`.

<!-- END no-session-termination addendum (CONST-036) -->

<!-- BEGIN anti-bluff-testing addendum (Article XI) -->

## Article XI — Anti-Bluff Testing (MANDATORY)

**Inherited from the umbrella project's Constitution Article XI.
Tests and Challenges that pass without exercising real end-user
behaviour are forbidden in this submodule too.**

Every test, every Challenge, every HelixQA bank entry MUST:

1. **Assert on a concrete end-user-visible outcome** — rendered DOM,
   DB rows that a real query would return, files on disk, media that
   actually plays, search results that actually contain expected
   items. Not "no error" or "200 OK".
2. **Run against the real system below the assertion.** Mocks/stubs
   are permitted ONLY in unit tests (`*_test.go` under `go test
   -short` or language equivalent). Integration / E2E / Challenge /
   HelixQA tests use real containers, real databases, real
   renderers. Unreachable real-system → skip with `SKIP-OK:
   #<ticket>`, never silently pass.
3. **Include a matching negative.** Every positive assertion is
   paired with an assertion that fails when the feature is broken.
4. **Emit copy-pasteable evidence** — body, screenshot, frame, DB
   row, log excerpt. Boolean pass/fail is insufficient.
5. **Verify "fails when feature is removed."** Author runs locally
   with the feature commented out; the test MUST FAIL. If it still
   passes, it's a bluff — delete and rewrite.
6. **No blind shells.** No `&& echo PASS`, `|| true`, `tee` exit
   laundering, `if [ -f file ]` without content assertion.

**Challenges in this submodule** must replay the user journey
end-to-end through the umbrella project's deliverables — never via
raw `curl` or third-party scripts. Sub-1-second Challenges almost
always indicate a bluff.

**HelixQA banks** declare executable actions
(`adb_shell:`, `playwright:`, `http:`, `assertVisible:`,
`assertNotVisible:`), never prose. Stagnation guard from Article I
§1.3 applies — frame N+1 identical to frame N for >10 s = FAIL.

**PR requirement:** every PR adding/modifying a test or Challenge in
this submodule MUST include a fenced `## Anti-Bluff Verification`
block with: (a) command run, (b) pasted output, (c) proof the test
fails when the feature is broken (second run with feature
commented-out showing FAIL).

**Cross-reference:** umbrella `CONSTITUTION.md` Article XI
(§§ 11.1 — 11.8).

<!-- END anti-bluff-testing addendum (Article XI) -->
