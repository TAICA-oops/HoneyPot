#!/usr/bin/env bash
# 一鍵啟動所有服務（後端 4 個 + 前端），使用 tmux 持久執行
# 適合 glows.ai — terminal 關掉服務照常跑
# 用法：cd HoneyPot/honeypot && bash scripts/start-all.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONEYPOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$HONEYPOT_DIR"

SESSION="honeypot"

# ── 前置檢查 ────────────────────────────
if [ ! -d ".venv" ]; then
    echo "❌ 尚未初始化，請先執行："
    echo "   bash scripts/setup.sh"
    exit 1
fi

if ! .venv/bin/python -c "import fastapi" 2>/dev/null; then
    echo "❌ Python 套件未安裝，請先執行："
    echo "   bash scripts/setup.sh"
    exit 1
fi

if [ ! -d "layer3/frontend/node_modules" ]; then
    echo "❌ 前端套件未安裝，請先執行："
    echo "   bash scripts/setup.sh"
    exit 1
fi

# ── tmux 啟動（推薦）────────────────────
if command -v tmux > /dev/null 2>&1; then
    # 砍掉舊的 session
    tmux kill-session -t "$SESSION" 2>/dev/null || true

    # 建立新 session，第一個 window 跑後端
    tmux new-session -d -s "$SESSION" -n "backend" \
        "cd '$HONEYPOT_DIR' && bash scripts/start.sh; echo '[backend stopped]'; read"

    # 第二個 window 跑前端
    tmux new-window -t "$SESSION" -n "frontend" \
        "cd '$HONEYPOT_DIR/layer3/frontend' && npm run dev; echo '[frontend stopped]'; read"

    # 切回 backend window
    tmux select-window -t "$SESSION:backend"

    echo ""
    echo "======================================"
    echo "  ✅ HoneyPot 已在 tmux 背景啟動"
    echo "======================================"
    echo ""
    echo "服務 Port："
    echo "  後端 SSH    → :2222    HTTP   → :8080"
    echo "  後端 LLM    → :8000    API    → :8001"
    echo "  前端        → :5173"
    echo ""
    echo "glows.ai Port Forwarding 需要開放："
    echo "  5173（Dashboard）、2222（SSH 蜜罐）、8080（HTTP 蜜罐）"
    echo ""
    echo "tmux 操作："
    echo "  進入：        tmux attach -t $SESSION"
    echo "  看後端 log：  tmux attach -t ${SESSION}:backend"
    echo "  看前端 log：  tmux attach -t ${SESSION}:frontend"
    echo "  停止全部：    tmux kill-session -t $SESSION"
    echo ""

# ── nohup 備案（沒有 tmux）──────────────
else
    echo "⚠️  tmux 未安裝，改用 nohup 背景執行..."
    echo "   建議安裝 tmux：sudo apt install -y tmux"
    echo ""

    # 砍掉已有的 process（|| true 避免 set -e 誤觸發）
    pkill -f "layer2.main:app" 2>/dev/null || true
    pkill -f "layer3.stats_api:app" 2>/dev/null || true
    pkill -f "layer1/ssh_server.py" 2>/dev/null || true
    pkill -f "layer1/http_server.py" 2>/dev/null || true
    pkill -f "vite" 2>/dev/null || true
    sleep 1

    nohup bash "$HONEYPOT_DIR/scripts/start.sh" \
        > "$HONEYPOT_DIR/honeypot-backend.log" 2>&1 &
    echo "後端已在背景啟動（日誌：honeypot-backend.log）"

    cd "$HONEYPOT_DIR/layer3/frontend"
    nohup npm run dev > "$HONEYPOT_DIR/honeypot-frontend.log" 2>&1 &
    FRONTEND_PID=$!
    cd "$HONEYPOT_DIR"

    sleep 2
    if ! kill -0 "$FRONTEND_PID" 2>/dev/null; then
        echo "⚠️  前端可能啟動失敗，請查看：honeypot-frontend.log"
    else
        echo "前端已在背景啟動（日誌：honeypot-frontend.log）"
    fi

    echo ""
    echo "✅ 所有服務已在背景啟動"
    echo "   查看日誌："
    echo "     tail -f honeypot-backend.log"
    echo "     tail -f honeypot-frontend.log"
fi
