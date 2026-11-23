#!/bin/bash
set -e

cd ~/libbpf-exp

# Kill any existing processes
pkill -f "build/auditor" 2>/dev/null || true
pkill -f "python3 main.py" 2>/dev/null || true
sleep 2

# Clean stale socket
rm -f /tmp/libbpf-exp.sock /tmp/middleman.log /tmp/auditor.log

# Start FastAPI middleman
echo "Starting FastAPI middleman..."
cd ~/libbpf-exp/middleman
python3 main.py > /tmp/middleman.log 2>&1 &
MIDDLEMAN_PID=$!
echo "Middleman PID: $MIDDLEMAN_PID"

# Wait for middleman to be ready
sleep 3
echo "Middleman log:"
cat /tmp/middleman.log

# Start auditor
echo "Starting auditor..."
cd ~/libbpf-exp
build/auditor /sys/fs/cgroup/denied > /tmp/auditor.log 2>&1 &
AUDITOR_PID=$!
echo "Auditor PID: $AUDITOR_PID"

sleep 3
echo "Auditor log:"
cat /tmp/auditor.log

echo ""
echo "=== Stack running ==="
echo "Middleman: http://localhost:8000 (WebSocket: ws://localhost:8000/ws)"
echo "Auditor PID: $AUDITOR_PID"
echo "Socket: /tmp/libbpf-exp.sock"
echo ""
echo "Open frontend/index.html in your browser to view the dashboard."
echo "Press Ctrl+C to stop."

# Wait for auditor
wait $AUDITOR_PID
