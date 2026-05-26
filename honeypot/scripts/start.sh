#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
PYTHON="$(pwd)/../.venv/bin/python"
UVICORN="$(pwd)/../.venv/bin/uvicorn"

echo "[*] Starting Layer 2 (LLM Engine)..."
$UVICORN layer2.main:app --port 8000 --log-level warning &
L2_PID=$!

sleep 1
echo "[*] Starting Layer 3 (Stats API)..."
$UVICORN layer3.stats_api:app --port 8001 --log-level warning &
L3_PID=$!

echo "[*] Starting Layer 1 SSH..."
$PYTHON layer1/ssh_server.py &
SSH_PID=$!

echo "[*] Starting Layer 1 HTTP..."
$PYTHON layer1/http_server.py &
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
