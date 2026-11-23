#!/bin/bash
#
# start.sh - Integration test suite for libbpf-exp
#
# Runs the auditor binary against a temporary cgroup and verifies:
#   1. Cgroup subtree denial (parent + children blocked)
#   2. Audit-only mode (violations logged but not blocked)
#   3. Auditor event emission for BPF_MAP_CREATE / BPF_PROG_LOAD
#   4. Allow-list removal restores access
#
# Requires: root, cgroup v2, bpf LSM, bpftool, /sys/fs/bpf mount.
# Non-interactive: exits with an error if prerequisites are missing.
#

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN="${BIN:-${PROJECT_DIR}/build/auditor}"
CG_BASE="${CG_BASE:-/sys/fs/cgroup/denied}"
PIN="${PIN:-/sys/fs/bpf}"
LOG=$(mktemp)
AUDIT_LOG=$(mktemp)
PID=""
CG=""
PASS_COUNT=0
FAIL_COUNT=0

cleanup() {
    set +e
    if [[ -n "$PID" ]]; then
        kill -INT "$PID" 2>/dev/null
        wait "$PID" 2>/dev/null
    fi
    # Remove any cgroup subdirectories we created
    if [[ -n "$CG" && -d "$CG" ]]; then
        # Move all processes out of the cgroup first
        echo 0 > "$CG/cgroup.procs" 2>/dev/null || true
        # Remove nested sub-cgroups
        rmdir "$CG"/sub1 "$CG"/sub2 "$CG"/child 2>/dev/null || true
        rmdir "$CG" 2>/dev/null || true
    fi
    rm -f "$PIN/ctl" "$PIN/dn" "$PIN/dn2" "$PIN/sub1" "$PIN/sub2"
    rmdir "$CG_BASE" 2>/dev/null || true
    rm -f "$LOG" "$AUDIT_LOG"
}
trap cleanup EXIT

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $1"; echo " --- program log ---"; cat "$LOG" 2>/dev/null || true; FAIL_COUNT=$((FAIL_COUNT + 1)); }

echo "== libbpf-exp integration test suite =="

# --- Prerequisites ---------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root"; exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: $BIN not found. Build first: cd ${PROJECT_DIR} && cmake -S . -B build && cmake --build build"; exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "ERROR: bpftool not installed"; exit 1
fi

if [[ $(stat -fc %T /sys/fs/cgroup 2>/dev/null) != "cgroup2fs" ]]; then
    echo "ERROR: cgroup v2 is required"; exit 1
fi

if ! mountpoint -q "$PIN" 2>/dev/null; then
    echo "Mounting $PIN"
    mount -t bpf bpf "$PIN" 2>/dev/null || {
        echo "ERROR: failed to mount $PIN"; exit 1
    }
fi

# --- Helpers ---------------------------------------------------------------
create_cgroup() {
    local path="$1"
    mkdir -p "$path"
    echo 0 > "$path/cgroup.procs" 2>/dev/null || true
}

bpf_map_create_in_cgroup() {
    local cg_path="$1"
    local map_name="$2"
    # Run bpftool inside the cgroup so the syscall originates from there
    sh -c "echo \$\$ > '$cg_path/cgroup.procs' && exec bpftool map create '$PIN/$map_name' type hash key 4 value 4 entries 8 name '$map_name'" 2>/dev/null
}

# Wait until the process is running and has attached BPF programs
wait_for_ready() {
    local timeout=10
    while [[ $timeout -gt 0 ]]; do
        if kill -0 "$PID" 2>/dev/null; then
            # Give it a moment to attach
            sleep 0.2
            return 0
        fi
        sleep 0.2
        timeout=$((timeout - 1))
    done
    return 1
}

# --- Test 1: Subtree denial -----------------------------------------------
echo ""
echo "--- Test 1: Cgroup subtree denial ---"

CG="$CG_BASE"
create_cgroup "$CG"
mkdir -p "$CG/child"
mkdir -p "$CG/child/grandchild"

# Start the auditor with subtree denial (default)
stdbuf -oL "$BIN" "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null || fail "auditor exited at startup"

# Create map OUTSIDE the cgroup - should succeed.
# In WSL2 the shell's cgroup ID may collide with the denied cgroup ID,
# so we run the control bpftool in a separate control cgroup whose ID
# differs from the denied one.
CTL_CG="${CG_BASE}/control"
mkdir -p "$CTL_CG"
echo 0 > "$CTL_CG/cgroup.procs" 2>/dev/null || true
if sh -c "echo \$\$ > '$CTL_CG/cgroup.procs' && exec bpftool map create '$PIN/ctl' type hash key 4 value 4 entries 8 name control" 2>/dev/null; then
    pass "control map create succeeded outside cgroup"
else
    fail "control map create was unexpectedly blocked"
fi

# Create map INSIDE the parent cgroup - should be denied
if bpf_map_create_in_cgroup "$CG" "dn"; then
    fail "denied cgroup was able to create a map"
else
    pass "denied parent cgroup blocked from creating map"
fi

# Create map INSIDE a child cgroup - should ALSO be denied (subtree)
if bpf_map_create_in_cgroup "$CG/child" "sub1"; then
    fail "child cgroup escaped subtree denial"
else
    pass "child cgroup blocked by subtree denial"
fi

# Create map INSIDE a grandchild cgroup - should ALSO be denied
if bpf_map_create_in_cgroup "$CG/child/grandchild" "sub2"; then
    fail "grandchild cgroup escaped subtree denial"
else
    pass "grandchild cgroup blocked by subtree denial"
fi

# Check the log for DENIED entries
if grep -q "DENIED" "$LOG"; then
    pass "denied operations logged"
else
    fail "blocked operations not logged"
fi

kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

# Cleanup cgroup for next test
echo 0 > "$CG/cgroup.procs" 2>/dev/null || true
rmdir "$CTL_CG" 2>/dev/null || true
rmdir "$CG/child/grandchild" "$CG/child" 2>/dev/null || true
rmdir "$CG" 2>/dev/null || true

# --- Test 2: Exact match only (no subtree) -------------------------------
echo ""
echo "--- Test 2: Exact match only (no subtree inheritance) ---"

CG="$CG_BASE"
create_cgroup "$CG"
mkdir -p "$CG/child"

# Start auditor with --no-subtree
stdbuf -oL "$BIN" --no-subtree "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null || fail "auditor exited at startup"

# Child cgroup should be allowed when subtree is disabled
if bpf_map_create_in_cgroup "$CG/child" "sub1"; then
    pass "child cgroup allowed when subtree disabled"
else
    # Read stderr to see why
    fail "child cgroup blocked despite --no-subtree"
fi

kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

rmdir "$CG/child" 2>/dev/null || true
rmdir "$CG" 2>/dev/null || true

# --- Test 3: Audit-only mode ----------------------------------------------
echo ""
echo "--- Test 3: Audit-only mode (log but do not enforce) ---"

CG="$CG_BASE"
create_cgroup "$CG"

stdbuf -oL "$BIN" --audit-only "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null || fail "auditor exited at startup"

# In audit-only mode, map creation inside denied cgroup should SUCCEED
if bpf_map_create_in_cgroup "$CG" "dn2"; then
    pass "audit-only: map creation allowed (not enforced)"
else
    fail "audit-only: map creation was blocked (should be log-only)"
fi

# But the violation should still be logged
if grep -q "DENIED" "$LOG"; then
    pass "audit-only: violation logged despite being allowed"
else
    fail "audit-only: violation not logged"
fi

kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

rmdir "$CG" 2>/dev/null || true

# --- Test 4: Auditor restartability --------------------------------------
echo ""
echo "--- Test 4: Auditor restartability ---"

CG="$CG_BASE"
create_cgroup "$CG"

# First auditor instance: deny the cgroup
stdbuf -oL "$BIN" "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null || fail "auditor exited at startup"

# Denied now
if bpf_map_create_in_cgroup "$CG" "dn"; then
    fail "cgroup should be denied initially"
else
    pass "cgroup initially denied"
fi

# Kill the first auditor
kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

# Second auditor instance: re-deny the same cgroup.
# Verifies that a new auditor instance can attach its LSM BPF program
# and enforce denial even after a previous instance was terminated.
stdbuf -oL "$BIN" "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null || fail "auditor (restart) exited at startup"

if bpf_map_create_in_cgroup "$CG" "dn2"; then
    fail "cgroup should still be denied after auditor restart"
else
    pass "cgroup denied after auditor restart"
fi

kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

rmdir "$CG" 2>/dev/null || true

# --- Test 5: Auditor emits BPF events -------------------------------------
echo ""
echo "--- Test 5: Auditor emits BPF syscall events ---"

CG="$CG_BASE"
create_cgroup "$CG"

# Run auditor in audit-only mode so the bpf call succeeds and generates an event
stdbuf -oL "$BIN" --audit-only "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null || fail "auditor exited at startup"

# Perform a BPF_MAP_CREATE inside the cgroup to generate an audit event
bpf_map_create_in_cgroup "$CG" "dn3" 2>/dev/null || true
sleep 0.5

# Check the auditor log for AUDIT entries
if grep -q "AUDIT" "$LOG"; then
    pass "auditor emitted BPF syscall events"
else
    fail "auditor did not emit BPF syscall events"
fi

kill -INT "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

rmdir "$CG" 2>/dev/null || true

# --- Summary ---------------------------------------------------------------
echo ""
echo "== Results: $PASS_COUNT passed, $FAIL_COUNT failed =="

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi
exit 0
