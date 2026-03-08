#!/usr/bin/env bash
# security_functionality_challenge.sh - Validates Security module core functionality
# Checks guardrails engine, PII detection/redaction, content filtering, policy enforcement, scanner
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_NAME="Security"

PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  FAIL: $1"; }

echo "=== ${MODULE_NAME} Functionality Challenge ==="
echo ""

# --- Section 1: Required packages ---
echo "Section 1: Required packages (5)"

for pkg in content guardrails pii policy scanner; do
    echo "Test: Package pkg/${pkg} exists"
    if [ -d "${MODULE_DIR}/pkg/${pkg}" ]; then
        pass "Package pkg/${pkg} exists"
    else
        fail "Package pkg/${pkg} missing"
    fi
done

# --- Section 2: Guardrails ---
echo ""
echo "Section 2: Guardrails engine"

echo "Test: Rule interface exists"
if grep -q "type Rule interface" "${MODULE_DIR}/pkg/guardrails/"*.go 2>/dev/null; then
    pass "Rule interface exists"
else
    fail "Rule interface missing"
fi

echo "Test: Engine struct exists"
if grep -q "type Engine struct" "${MODULE_DIR}/pkg/guardrails/"*.go 2>/dev/null; then
    pass "Guardrails Engine struct exists"
else
    fail "Guardrails Engine struct missing"
fi

echo "Test: Result struct exists in guardrails"
if grep -q "type Result struct" "${MODULE_DIR}/pkg/guardrails/"*.go 2>/dev/null; then
    pass "Result struct exists in guardrails"
else
    fail "Result struct missing in guardrails"
fi

echo "Test: MaxLengthRule struct exists"
if grep -q "type MaxLengthRule struct" "${MODULE_DIR}/pkg/guardrails/"*.go 2>/dev/null; then
    pass "MaxLengthRule struct exists"
else
    fail "MaxLengthRule struct missing"
fi

echo "Test: ForbiddenPatternsRule struct exists"
if grep -q "type ForbiddenPatternsRule struct" "${MODULE_DIR}/pkg/guardrails/"*.go 2>/dev/null; then
    pass "ForbiddenPatternsRule struct exists"
else
    fail "ForbiddenPatternsRule struct missing"
fi

# --- Section 3: PII detection ---
echo ""
echo "Section 3: PII detection and redaction"

echo "Test: Detector interface exists"
if grep -q "type Detector interface" "${MODULE_DIR}/pkg/pii/"*.go 2>/dev/null; then
    pass "PII Detector interface exists"
else
    fail "PII Detector interface missing"
fi

echo "Test: Match struct exists"
if grep -q "type Match struct" "${MODULE_DIR}/pkg/pii/"*.go 2>/dev/null; then
    pass "PII Match struct exists"
else
    fail "PII Match struct missing"
fi

echo "Test: Redactor struct exists"
if grep -q "type Redactor struct" "${MODULE_DIR}/pkg/pii/"*.go 2>/dev/null; then
    pass "PII Redactor struct exists"
else
    fail "PII Redactor struct missing"
fi

# --- Section 4: Content filtering ---
echo ""
echo "Section 4: Content filtering"

echo "Test: Filter interface exists"
if grep -q "type Filter interface" "${MODULE_DIR}/pkg/content/"*.go 2>/dev/null; then
    pass "Content Filter interface exists"
else
    fail "Content Filter interface missing"
fi

echo "Test: ChainFilter struct exists"
if grep -q "type ChainFilter struct" "${MODULE_DIR}/pkg/content/"*.go 2>/dev/null; then
    pass "ChainFilter struct exists"
else
    fail "ChainFilter struct missing"
fi

echo "Test: KeywordFilter struct exists"
if grep -q "type KeywordFilter struct" "${MODULE_DIR}/pkg/content/"*.go 2>/dev/null; then
    pass "KeywordFilter struct exists"
else
    fail "KeywordFilter struct missing"
fi

echo "Test: FilterResult struct exists"
if grep -q "type FilterResult struct" "${MODULE_DIR}/pkg/content/"*.go 2>/dev/null; then
    pass "FilterResult struct exists"
else
    fail "FilterResult struct missing"
fi

# --- Section 5: Policy enforcement ---
echo ""
echo "Section 5: Policy enforcement"

echo "Test: Policy struct exists"
if grep -q "type Policy struct" "${MODULE_DIR}/pkg/policy/"*.go 2>/dev/null; then
    pass "Policy struct exists"
else
    fail "Policy struct missing"
fi

echo "Test: Enforcer struct exists"
if grep -q "type Enforcer struct" "${MODULE_DIR}/pkg/policy/"*.go 2>/dev/null; then
    pass "Enforcer struct exists"
else
    fail "Enforcer struct missing"
fi

echo "Test: EvaluationContext struct exists"
if grep -q "type EvaluationContext struct" "${MODULE_DIR}/pkg/policy/"*.go 2>/dev/null; then
    pass "EvaluationContext struct exists"
else
    fail "EvaluationContext struct missing"
fi

# --- Section 6: Vulnerability scanner ---
echo ""
echo "Section 6: Vulnerability scanner"

echo "Test: Scanner interface exists"
if grep -q "type Scanner interface" "${MODULE_DIR}/pkg/scanner/"*.go 2>/dev/null; then
    pass "Scanner interface exists"
else
    fail "Scanner interface missing"
fi

echo "Test: Finding struct exists"
if grep -q "type Finding struct" "${MODULE_DIR}/pkg/scanner/"*.go 2>/dev/null; then
    pass "Finding struct exists"
else
    fail "Finding struct missing"
fi

echo "Test: Report struct exists in scanner"
if grep -q "type Report struct" "${MODULE_DIR}/pkg/scanner/"*.go 2>/dev/null; then
    pass "Report struct exists in scanner"
else
    fail "Report struct missing in scanner"
fi

# --- Section 7: Source structure completeness ---
echo ""
echo "Section 7: Source structure"

echo "Test: Each package has non-test Go source files"
all_have_source=true
for pkg in content guardrails pii policy scanner; do
    non_test=$(find "${MODULE_DIR}/pkg/${pkg}" -name "*.go" ! -name "*_test.go" -type f 2>/dev/null | wc -l)
    if [ "$non_test" -eq 0 ]; then
        fail "Package pkg/${pkg} has no non-test Go files"
        all_have_source=false
    fi
done
if [ "$all_have_source" = true ]; then
    pass "All packages have non-test Go source files"
fi

echo ""
echo "=== Results: ${PASS}/${TOTAL} passed, ${FAIL} failed ==="
[ "${FAIL}" -eq 0 ] && exit 0 || exit 1
