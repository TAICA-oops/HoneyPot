#!/usr/bin/env bash
# 初次建置腳本：建立環境、安裝套件、檢查 Ollama 模型
# 用法：cd HoneyPot/honeypot && bash scripts/setup.sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HONEYPOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$HONEYPOT_DIR"

echo "======================================"
echo "  HoneyPot 初始化設置"
echo "======================================"
echo ""

# ── 1. Python 虛擬環境 ──────────────────
if [ ! -d ".venv" ]; then
    echo "[1/5] 建立 Python 虛擬環境..."
    python3 -m venv .venv
    echo "  ✓ .venv 建立完成"
else
    echo "[1/5] 虛擬環境已存在，跳過"
fi

# ── 2. Python 套件 ──────────────────────
echo "[2/5] 安裝 Python 套件..."
.venv/bin/pip install -e . -q
echo "  ✓ 套件安裝完成"

# ── 3. 前端套件 ─────────────────────────
if [ -d "layer3/frontend" ]; then
    echo "[3/5] 安裝前端套件（npm install）..."
    cd layer3/frontend
    npm install --silent
    cd "$HONEYPOT_DIR"
    echo "  ✓ 前端套件安裝完成"
else
    echo "[3/5] 找不到前端目錄，跳過"
fi

# ── 4. Ollama 檢查 ──────────────────────
echo "[4/5] 檢查 Ollama 連線..."
SKIP_MODELS=0
if ! curl -s --max-time 3 http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "  ⚠️  Ollama 目前未在執行（或尚未安裝）"
    echo "     在 glows.ai 上 Ollama 通常已預裝，請確認服務已啟動"
    echo "     跳過模型下載，設置繼續..."
    SKIP_MODELS=1
fi

# ── 5. Ollama 模型 ──────────────────────
if [ "$SKIP_MODELS" -eq 0 ]; then
    echo "[5/5] 檢查 Ollama 模型..."

    # 從 .env 讀取模型名稱（加 || true 避免 set -e 因 grep 無結果而中止）
    TERMINAL_MODEL=""
    REPORT_MODEL=""
    if [ -f ".env" ]; then
        TERMINAL_MODEL=$(grep "^OLLAMA_MODEL=" .env | cut -d= -f2 | tr -d '[:space:]') || true
        REPORT_MODEL=$(grep "^OLLAMA_REPORT_MODEL=" .env | cut -d= -f2 | tr -d '[:space:]') || true
    fi
    TERMINAL_MODEL="${TERMINAL_MODEL:-llama3.1:8b-instruct-q8_0}"
    REPORT_MODEL="${REPORT_MODEL:-qwen2.5:14b-instruct-q4_K_M}"

    pull_if_missing() {
        local model="$1"
        # 用 awk 取第一欄（NAME 欄）做嚴格比對，避免 partial match
        if ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qxF "$model"; then
            echo "  ✓ $model 已存在"
        else
            echo "  ↓ 下載 $model（可能需要數分鐘）..."
            ollama pull "$model"
            echo "  ✓ $model 下載完成"
        fi
    }

    pull_if_missing "$TERMINAL_MODEL"
    pull_if_missing "$REPORT_MODEL"
else
    echo "[5/5] 略過模型檢查（Ollama 未執行）"
    echo "     之後可手動執行："
    echo "       ollama pull llama3.1:8b-instruct-q8_0"
    echo "       ollama pull qwen2.5:14b-instruct-q4_K_M"
fi

# ── 完成 ────────────────────────────────
echo ""
echo "======================================"
echo "  ✅ 初始化完成！"
echo "======================================"
echo ""
echo "下一步 — 啟動所有服務："
echo "  bash scripts/start-all.sh"
echo ""
echo "或分開啟動："
echo "  後端：bash scripts/start.sh"
echo "  前端：cd layer3/frontend && npm run dev"
