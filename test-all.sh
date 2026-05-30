#!/usr/bin/env bash
set -euo pipefail

echo "╔══════════════════════════════════════════════════════════╗"
echo "║     SecureVault — Full Cross-Platform Test Suite        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { PASS=$((PASS + 1)); echo -e "  ${GREEN}✅ PASS${NC}  $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "  ${RED}❌ FAIL${NC}  $1"; }

run() {
    local name=$1
    shift
    echo "--- $name ---"
    if "$@" 2>&1; then
        pass "$name"
    else
        fail "$name"
    fi
    echo ""
}

cd "$(dirname "$0")"

# ── 1. Backend (Java) ──
run "Backend unit tests (6)" mvn -q test

# ── 2. Web (TypeScript) ──
run "Web TypeScript build"   bash -c "cd web && npm run build 2>/dev/null"
run "Web vitest (24 tests)"  bash -c "cd web && npm test 2>/dev/null | grep -q 'Tests.*passed'"

# ── 3. Rust crypto-core ──
run "Rust unit tests (37)"   bash -c "cd crypto-core && cargo test --lib -q 2>&1 | grep -q 'test result: ok'"
run "Rust integration (2)"   bash -c "cd crypto-core && cargo test --test vectors -q 2>&1 | grep -q 'test result: ok'"

# ── 4. Android ──
run "Android compile"        bash -c "cd mobile && ./gradlew :app:compileDebugKotlinAndroid 2>/dev/null | grep -q 'BUILD SUCCESSFUL'"
run "Android unit tests (33)" bash -c "cd mobile && ./gradlew :app:testDebugUnitTest 2>/dev/null | grep -q 'BUILD SUCCESSFUL'"

# ── 5. iOS ──
run "iOS compile"            bash -c "cd mobile && ./gradlew :app:compileKotlinIosSimulatorArm64 2>/dev/null | grep -q 'BUILD SUCCESSFUL'"
run "iOS unit tests (12)"    bash -c "cd mobile && ./gradlew :app:iosSimulatorArm64Test 2>/dev/null | grep -q 'BUILD SUCCESSFUL'"

# ── 6. End-to-end (requires local Docker backend) ──
if curl -sf http://localhost:8080/api/v1/health > /dev/null 2>&1; then
    run "End-to-end flow"      bash -c "mvn -q compile test-compile && mvn -q exec:java -Dexec.mainClass='com.securevault.FullFlowTest' -Dexec.classpathScope=test 2>/dev/null | grep -q 'ALL E2E TESTS PASSED'"
else
    echo "--- End-to-end flow ---"
    echo -e "  ${RED}⚠ SKIP${NC}  Backend not running on localhost:8080"
    echo ""
fi

# ── Summary ──
echo "══════════════════════════════════════════════════════════"
echo -e "  ${GREEN}${PASS} passed${NC}  |  ${RED}${FAIL} failed${NC}"
echo "══════════════════════════════════════════════════════════"
exit $FAIL
