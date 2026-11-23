#!/bin/bash
set -e

echo "=== BTF Certification ==="
ls -la /sys/kernel/btf/vmlinux
echo ""
bpftool feature 2>&1 | grep -iE 'CONFIG_BPF|DEBUG_INFO_BTF|CONFIG_CGROUPS' | head -10
echo ""

echo "=== Python Dependencies ==="
pip3 install --break-system-packages -q fastapi uvicorn websockets 2>&1 | tail -3
echo "Python deps done"

echo ""
echo "=== Frontend (standalone HTML - no build needed) ==="
ls -la ~/libbpf-exp/frontend/index.html
echo "Frontend ready (use frontend/index.html directly in browser)"

echo ""
echo "=== Build artifacts ==="
ls -la ~/libbpf-exp/build/auditor
echo ""
echo "=== Setup complete ==="
echo "Project location: ~/libbpf-exp"
echo "Auditor binary: ~/libbpf-exp/build/auditor"
echo "Frontend: ~/libbpf-exp/frontend/index.html"
echo "Middleman: ~/libbpf-exp/middleman/main.py"
