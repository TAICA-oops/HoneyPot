#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

echo "[*] Starting Layer 2 (LLM Engine)..."
.venv/bin/uvicorn layer2.main:app --port 8000 --log-level warning &
L2_PID=$!

sleep 1
echo "[*] Starting Layer 3 (Stats API)..."
.venv/bin/uvicorn layer3.stats_api:app --port 8001 --log-level warning &
L3_PID=$!

echo "[*] Starting Layer 1 SSH..."
.venv/bin/python layer1/ssh_server.py &
SSH_PID=$!

echo "[*] Starting Layer 1 HTTP..."
.venv/bin/python layer1/http_server.py &
HTTP_PID=$!

echo ""
echo "HoneyPot running:"
echo "  SSH    → port 2222"
echo "  HTTP   → port 8080"
echo "  LLM    → port 8000"
echo "  API    → port 8001"
echo ""
echo "Press Ctrl+C to stop all services"
trap "kill $L2_PID $L3_PID $SSH_PID $HTTP_PID 2>/dev/null; exit 0" INT
wait
