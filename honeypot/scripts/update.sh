#!/usr/bin/env bash
# 更新腳本：拉取最新程式碼並重啟所有服務
# 用法：cd HoneyPot/honeypot && bash scripts/update.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONEYPOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$HONEYPOT_DIR/.." && pwd)"

echo "======================================"
echo "  HoneyPot 更新"
echo "======================================"
echo ""

# ── 1. Git pull ─────────────────────────
echo "[1/4] 拉取最新程式碼..."
cd "$REPO_DIR"
git pull origin main
cd "$HONEYPOT_DIR"
echo "  ✓ 程式碼已更新"

# ── 2. 更新 Python 套件 ─────────────────
echo "[2/4] 更新 Python 套件..."
.venv/bin/pip install -e . -q
echo "  ✓ 套件已更新"

# ── 3. 更新前端套件 ─────────────────────
echo "[3/4] 更新前端套件..."
cd "$HONEYPOT_DIR/layer3/frontend"
npm install --silent
cd "$HONEYPOT_DIR"
echo "  ✓ 前端套件已更新"

# ── 4. 重啟服務 ─────────────────────────
echo "[4/4] 重啟服務..."

SESSION="honeypot"
if command -v tmux > /dev/null 2>&1 && tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "  停止舊的 tmux session..."
    tmux kill-session -t "$SESSION"
    sleep 1
    bash "$HONEYPOT_DIR/scripts/start-all.sh"
else
    # 砍掉所有相關 process（|| true 避免 set -e 誤觸發）
    pkill -f "layer2.main:app" 2>/dev/null || true
    pkill -f "layer3.stats_api:app" 2>/dev/null || true
    pkill -f "layer1/ssh_server.py" 2>/dev/null || true
    pkill -f "layer1/http_server.py" 2>/dev/null || true
    pkill -f "vite" 2>/dev/null || true
    sleep 1

    # 重啟後端
    nohup bash "$HONEYPOT_DIR/scripts/start.sh" \
        > "$HONEYPOT_DIR/honeypot-backend.log" 2>&1 &
    echo "  ✓ 後端已重啟（日誌：honeypot-backend.log）"

    # 重啟前端
    cd "$HONEYPOT_DIR/layer3/frontend"
    nohup npm run dev > "$HONEYPOT_DIR/honeypot-frontend.log" 2>&1 &
    FRONTEND_PID=$!
    cd "$HONEYPOT_DIR"
    sleep 2
    if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
        echo "  ⚠️  前端可能啟動失敗，請查看：honeypot-frontend.log"
    else
        echo "  ✓ 前端已重啟（日誌：honeypot-frontend.log）"
    fi
fi

echo ""
echo "✅ 更新完成"
