#!/usr/bin/env bash
# 更新腳本：拉取最新程式碼並重啟所有服務
# 用法：bash scripts/update.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONEYPOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"   # HoneyPot/honeypot/
REPO_DIR="$(cd "$HONEYPOT_DIR/.." && pwd)"      # HoneyPot/（git root）

echo "======================================"
echo "  HoneyPot 更新"
echo "======================================"
echo ""

# ── 1. Git pull ─────────────────────────
echo "[1/3] 拉取最新程式碼..."
cd "$REPO_DIR"
git pull origin main
cd "$HONEYPOT_DIR"
echo "  ✓ 程式碼已更新"

# ── 2. 更新 Python 套件 ─────────────────
echo "[2/3] 更新 Python 套件..."
.venv/bin/pip install -e . -q
echo "  ✓ 套件已更新"

# ── 3. 重啟服務 ─────────────────────────
echo "[3/3] 重啟服務..."

SESSION="honeypot"
if command -v tmux > /dev/null 2>&1 && tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "  停止舊的 tmux session..."
    tmux kill-session -t "$SESSION"
    sleep 1
    bash "$HONEYPOT_DIR/scripts/start-all.sh"
else
    # 沒有 tmux session，砍 process 後重啟
    pkill -f "layer2.main:app" 2>/dev/null || true
    pkill -f "layer3.stats_api:app" 2>/dev/null || true
    pkill -f "layer1/ssh_server.py" 2>/dev/null || true
    pkill -f "layer1/http_server.py" 2>/dev/null || true
    sleep 1
    nohup bash "$HONEYPOT_DIR/scripts/start.sh" \
        > "$HONEYPOT_DIR/honeypot-backend.log" 2>&1 &
    echo "  ✓ 後端已重啟（日誌：honeypot-backend.log）"
fi

echo ""
echo "✅ 更新完成"
