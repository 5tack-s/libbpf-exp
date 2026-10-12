#!/bin/bash
set -euo pipefail

BIN="${BIN:-build/auditor}"
CG=/sys/fs/cgroup/denied
PIN=/sys/fs/bpf
LOG=$(mktemp)
PID=""

if [[ "$EUID" -ne 0 ]]; then
    echo "Run this script with sudo"
    exit 1
fi

cleanup() {
    set +e
    if [[ -n $PID ]]; then
        kill -INT "$PID" 2>/dev/null
        wait "$PID" 2>/dev/null
    fi
    rm -f "$PIN/ctl" "$PIN/dn" "$PIN/dn2" "$PIN/sub1"
    rmdir "$CG/sub" "$CG" 2>/dev/null
}

trap cleanup EXIT

pass() { echo "PASS: $1"; }
fail() { echo "FAIL: $1"; echo " --- program log ---"; cat "$LOG"; exit 1; }

#Prequesites
if [[ $(stat -fc %T /sys/fs/cgroup) != "cgroup2fs" ]]; then
    echo "cgroup v2 is required"; exit 1
fi

if [[ "$(cat /sys/kernel/security/lsm)" != *bpf* ]]; then
    echo "'bpf' is not in the active LSM list (check lsm= on the kernel cmdline)"; exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool is not installed"; exit 1
fi

if [[ ! -x $BIN ]]; then
    echo "build/auditor is required. Compile or set BIN="; exit 1
fi

if ! mountpoint -q "$PIN"; then
    read -r -p "$PIN is not mounted. Mount it? (y/n): " should_mount

    if [[ ${should_mount,,} == y ]]; then
        echo "Mounting /sys/fs/bpf"
        mount -t bpf bpf /sys/fs/bpf
        echo "Mounted"
    else exit 1;
    fi
fi

#Setup
mkdir -p "$CG"
echo "denied cgroup_id: $(stat -c %i "$CG")"

stdbuf -oL "$BIN" "$CG" > "$LOG" 2>&1 &
PID=$!
sleep 1
kill -0 "$PID" 2>/dev/null  || fail "program exited at startup"

#TESTS

#1 creating a map outside the cgroup
#it must succeed since the tool operates on a blacklist
if bpftool map create "$PIN/ctl" type hash key 4 value 4 entries 8 name control 2>/dev/null; then
    pass "control map create succeeded"
else
    fail "control map create was unfortunately blocked"
fi

#2 creating a map inside the denied cgroup
#it must fail since it has been blacklisted
ERR=$(mktemp)
if sh -c "echo \$\$ > $CG/cgroup.procs && exec bpftool map create $PIN/dn type hash key 4 value 4 entries 8 name dn" 2>"$ERR"; then
  fail "denied cgroup was able to create a map"
fi
grep -qi "operation not permitted" "$ERR" || { cat "$ERR"; fail "failed, but not with EPERM"; }
[[ ! -e $PIN/dn ]] || fail "dn was pinned despite denial"
sleep 1
grep -q "DENIED" "$LOG" && pass "denied map create blocked and logged" || fail "blocked, but no DENIED line in log"
rm -f "$ERR"

#3 creating a map from a child cgroup
# normally children inherit the limitations from the node cgroup
# however this tool operates on exact match
# thus it should be allowed
mkdir -p "$CG/sub"
if sh -c "echo \$\$ > $CG/sub/cgroup.procs; exec bpftool map create $PIN/sub1 type hash key 4 value 4 entries 8 name sub1" 2>/dev/null; then
    pass "child cgroup allowed"
else
    fail "child cgroup blocked"
fi

#4 delete the key from denied cgroup
ID=$(stat -c %i "$CG")
KEY=""
for i in {0..7}; do
    KEY+=$(printf '%02x ' $(( (ID >> (8*i)) &0xff )) )
done
bpftool map delete name denied_cgroups key hex $KEY || fail "could not delete cgroup from denylist"

if sh -c "echo \$\$ > $CG/cgroup.procs; exec bpftool map create $PIN/dn2 type hash key 4 value 4 entries 8 name dn2" 2>/dev/null; then
    pass "allowed again after removal from denylist"
else
    fail "still blocked after removal"
fi

echo "All tests passed!"