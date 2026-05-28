#!/usr/bin/env bash
# 啟動後端四個服務（Layer 1 SSH/HTTP、Layer 2 LLM、Layer 3 Stats API）
# 用法：cd honeypot && bash scripts/start.sh
set -e
cd "$(dirname "$0")/.."

PYTHON="$(pwd)/.venv/bin/python"
UVICORN="$(pwd)/.venv/bin/uvicorn"

# 從 .env 讀取 port（有 .env 就用，否則用預設值）
LLM_PORT=8000
STATS_PORT=8001
SSH_PORT=2222
HTTP_PORT=8080
if [ -f ".env" ]; then
    _val=$(grep "^LLM_ENGINE_PORT=" .env | cut -d= -f2 | tr -d '[:space:]')
    [ -n "$_val" ] && LLM_PORT=$_val
    _val=$(grep "^STATS_API_PORT=" .env | cut -d= -f2 | tr -d '[:space:]')
    [ -n "$_val" ] && STATS_PORT=$_val
    _val=$(grep "^SSH_PORT=" .env | cut -d= -f2 | tr -d '[:space:]')
    [ -n "$_val" ] && SSH_PORT=$_val
    _val=$(grep "^HTTP_PORT=" .env | cut -d= -f2 | tr -d '[:space:]')
    [ -n "$_val" ] && HTTP_PORT=$_val
fi

echo "[*] Starting Layer 2 (LLM Engine) on :${LLM_PORT}..."
$UVICORN layer2.main:app --port "$LLM_PORT" --log-level warning &
L2_PID=$!

sleep 1
echo "[*] Starting Layer 3 (Stats API) on :${STATS_PORT}..."
$UVICORN layer3.stats_api:app --port "$STATS_PORT" --log-level warning &
L3_PID=$!

echo "[*] Starting Layer 1 SSH on :${SSH_PORT}..."
$PYTHON layer1/ssh_server.py &
SSH_PID=$!

echo "[*] Starting Layer 1 HTTP on :${HTTP_PORT}..."
$PYTHON layer1/http_server.py &
HTTP_PID=$!

echo ""
echo "HoneyPot running:"
echo "  SSH    → port ${SSH_PORT}"
echo "  HTTP   → port ${HTTP_PORT}"
echo "  LLM    → port ${LLM_PORT}"
echo "  API    → port ${STATS_PORT}"
echo ""
echo "Press Ctrl+C to stop all services"
trap "kill $L2_PID $L3_PID $SSH_PID $HTTP_PID 2>/dev/null; exit 0" INT
wait
