#!/bin/bash
# Kill all python processes related to middleman
pkill -f "main.py" 2>/dev/null || true
sleep 2
echo "Old processes killed"

# Clean up
rm -f /tmp/libbpf-exp.sock /tmp/libbpf-exp-test.sock /tmp/middleman.log

# Start fresh middleman on port 8000
cd ~/libbpf-exp/middleman
nohup python3 main.py > /tmp/middleman.log 2>&1 &
sleep 4
echo "=== Middleman log ==="
cat /tmp/middleman.log
echo ""
echo "=== Process check ==="
ps aux | grep python | grep -v grep
