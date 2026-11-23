#!/bin/bash
# start-monitor.sh - Launch the full frontend monitor stack
#
# Starts:
#   1. The FastAPI middleman (background)
#   2. The eBPF auditor (foreground, requires root)
#   3. Optionally the Vue frontend dev server
#
# Usage:
#   sudo ./start-monitor.sh [--no-frontend]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

MIDDLEMAN_DIR="${PROJECT_DIR}/middleman"
FRONTEND_DIR="${PROJECT_DIR}/frontend"
AUDITOR_BIN="${PROJECT_DIR}/build/auditor"
SOCK_PATH="/tmp/libbpf-exp.sock"

CGROUP_PATH="${CG_BASE:-/sys/fs/cgroup/denied}"
NO_FRONTEND=0

if [[ "${1:-}" == "--no-frontend" ]]; then
    NO_FRONTEND=1
fi

# --- Prerequisites ---------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: must run as root (eBPF LSM attachment requires root)"; exit 1
fi

if [[ ! -x "$AUDITOR_BIN" ]]; then
    echo "ERROR: auditor binary not found at $AUDITOR_BIN"
    echo "       Build first: cmake -S . -B build && cmake --build build"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found"; exit 1
fi

# Clean stale socket
rm -f "$SOCK_PATH"

# --- Create cgroup ---------------------------------------------------------
echo "[monitor] Creating cgroup $CGROUP_PATH..."
mkdir -p "$CGROUP_PATH"
# Ensure the cgroup is empty and ready for use
echo 0 > "$CGROUP_PATH/cgroup.procs" 2>/dev/null || true

# --- Start FastAPI middleman ----------------------------------------------
echo "[monitor] Setting up Python virtualenv in $MIDDLEMAN_DIR/.venv..."
if [[ ! -d "$MIDDLEMAN_DIR/.venv" ]]; then
    python3 -m venv "$MIDDLEMAN_DIR/.venv"
fi
"$MIDDLEMAN_DIR/.venv/bin/pip" install -q -r "$MIDDLEMAN_DIR/requirements.txt"

echo "[monitor] Starting FastAPI middleman on :8000..."
cd "$MIDDLEMAN_DIR"
"$MIDDLEMAN_DIR/.venv/bin/python" main.py &
MIDDLEMAN_PID=$!
cd "$PROJECT_DIR"

# Wait for middleman to be ready
for i in $(seq 1 30); do
    if python3 -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', 8000)); s.close()" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# --- Start Vue frontend (dev server) --------------------------------------
FRONTEND_PID=""
if [[ "$NO_FRONTEND" -eq 0 ]]; then
    if command -v npm >/dev/null 2>&1; then
        echo "[monitor] Starting Vue frontend dev server on :5173..."
        cd "$FRONTEND_DIR"
        if [[ ! -d node_modules ]]; then
            echo "[monitor] Installing frontend dependencies (npm install)..."
            npm install
        fi
        npm run dev &
        FRONTEND_PID=$!
        cd "$PROJECT_DIR"
    else
        echo "[monitor] npm not found; skipping frontend dev server."
        echo "[monitor] Open frontend/index.html directly in your browser."
        echo "[monitor] It connects to ws://localhost:8000/ws (no build needed)."
    fi
fi

# --- Start eBPF auditor ----------------------------------------------------
echo "[monitor] Starting eBPF auditor (cgroup: $CGROUP_PATH)..."
echo "[monitor] Events will stream to http://localhost:8000 (API) and :5173 (UI)"
echo "[monitor] Press Ctrl+C to stop all services."

cleanup() {
    echo ""
    echo "[monitor] Shutting down..."
    kill "$AUDITOR_PID" 2>/dev/null || true
    kill "$MIDDLEMAN_PID" 2>/dev/null || true
    [[ -n "$FRONTEND_PID" ]] && kill "$FRONTEND_PID" 2>/dev/null || true
    # Move all processes out of the cgroup and remove it
    if [[ -d "$CGROUP_PATH" ]]; then
        echo 0 > "$CGROUP_PATH/cgroup.procs" 2>/dev/null || true
        rmdir "$CGROUP_PATH" 2>/dev/null || true
    fi
    rm -f "$SOCK_PATH"
    wait 2>/dev/null || true
    echo "[monitor] All services stopped."
}
trap cleanup EXIT INT TERM

# Run auditor in foreground
"$AUDITOR_BIN" "$CGROUP_PATH" &
AUDITOR_PID=$!
wait "$AUDITOR_PID"
