#!/bin/bash
set -e

echo "=== Checking port 8000 ==="
python3 -c '
import socket
s = socket.socket()
try:
    s.bind(("0.0.0.0", 8000))
    s.close()
    print("Port 8000 is FREE")
except OSError as e:
    print(f"Port 8000 is IN USE: {e}")
finally:
    s.close()
'

echo ""
echo "=== Checking socket file ==="
ls -la /tmp/libbpf-exp.sock 2>&1 || echo "Socket file does not exist"

echo ""
echo "=== Checking middleman process ==="
ps aux | grep "main.py" | grep -v grep || echo "No middleman process running"
