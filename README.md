# LLM 驅動蜜罐系統

一個高互動型蜜罐，將攻擊者困在擬真的假 Linux 伺服器和 WordPress 網站中，由本地 LLM 即時生成回應。每個指令都會被分類攻擊意圖、記錄至 SQLite，並在即時 React Dashboard 上呈現，最終自動生成威脅情報報告。

---

## 系統架構

```
攻擊者
  ├─ SSH :2222 ──┐
  └─ HTTP :8080 ─┤
                 ▼
         Layer 1 — 蜜罐伺服器
         (Session 狀態管理、日誌記錄、串流回應)
                 │ POST /respond
                 ▼
         Layer 2 — LLM 引擎 :8000
         (規則快取 → Ollama → 意圖分類器)
                 │ SQLite
                 ▼
         Layer 3 — Dashboard :8001 + Vercel
         (即時攻擊串流、統計圖表、威脅報告)
```

**SSH 人設：** Ubuntu 18.04.6 LTS 電商後台伺服器。只接受常見弱密碼（admin/admin、root/toor、dbadmin/Sup3rS3cr3t!2019 等）登入。常見指令（ls、cat、pwd）直接從規則快取秒回，配備完整的假檔案系統——包含假資料庫憑證的 `/var/www/html/.env`、`/home/admin/backup.sql` MySQL dump、`/home/dbadmin/.my.cnf`（MySQL client 設定，含明文密碼），以及設定錯誤的 sudoers 等誘餌檔案。陌生指令才送 LLM 生成回應。LLM 對 `ls`、`cat`、`find` 等讀取指令的回應會跨 session 快取，確保不同攻擊者看到一致的假檔案系統狀態。

**HTTP 人設：** 假 WordPress 網站。回應 `/wp-admin`、`/wp-login.php`（記錄攻擊者輸入的帳密）、`/.env`（誘餌檔）、`/phpmyadmin`、`/xmlrpc.php`，其他路徑回傳 WordPress 風格的 404。

**意圖分類器：** 關鍵字比對，將 SSH 指令和 HTTP 請求分為 `reconnaissance`（偵查）、`privilege_escalation`（提權）、`data_exfiltration`（資料外洩）、`persistence`（持久化）、`lateral_movement`（橫向移動）、`credential_harvesting`（帳密竊取）、`web_recon`（網站偵查）、`injection_attempt`（注入攻擊）。快速路徑處理 80% 以上的情況，不需呼叫 LLM。

**威脅報告：** Session 結束時自動觸發，包含 Executive Summary、攻擊時間軸、IoC 指標、威脅等級（Low / Medium / High / Critical）。

---

## 環境需求

| | glows.ai | 自己電腦 |
|---|---|---|
| Python | ✅ 已內建 | 需要 3.10+ |
| Ollama | ✅ 已在跑 | 需要自行安裝 |
| Node.js | 僅 Dashboard 需要 | 僅 Dashboard 需要 |
| Docker | ❌ 不支援 | ✅ 可選用 |

---

## 在 glows.ai 上啟動

請參閱 **[GLOWS.md](GLOWS.md)**，包含一鍵初始化、tmux 啟動、Port Forwarding 設定等完整說明。

```bash
# 快速三步驟
git clone https://github.com/TAICA-oops/HoneyPot.git
cd HoneyPot/honeypot && bash scripts/setup.sh    # 初始化（含 Ollama 模型）
bash scripts/start-all.sh                         # 啟動所有服務
```

> **映像選擇**：建議選 **N8N 2.1.4 & Ollama 0.13.5**（內建 Ollama + Node.js）。若 `setup.sh` 報 `npm: command not found`，先執行：
> ```bash
> curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs
> ```

---

## 在自己電腦上啟動

### 方法 A：直接用 start.sh

#### 1. 安裝 Ollama

至 [ollama.ai](https://ollama.ai) 下載安裝，然後：

```bash
ollama pull llama3.1:8b-instruct-q8_0            # 終端回應模型（快速，~8.5GB VRAM）
ollama pull qwen2.5:14b-instruct-q4_K_M          # 報告生成模型（高品質，~9GB VRAM）
```

#### 2. 安裝 Python 套件

```bash
cd honeypot
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

#### 3. 設定

`honeypot/.env` 預設值即可，不需要改。

#### 4. Terminal 1 — 啟動後端所有服務

```bash
cd honeypot
./scripts/start.sh
```

**這個 terminal 要一直開著**，按 `Ctrl+C` 全部停止。

確認服務正常：
```bash
curl http://localhost:8000/health        # 應回傳 {"status":"ok"}
curl http://localhost:8001/api/sessions  # 應回傳 []
```

#### 5. Terminal 2 — 啟動 Dashboard 前端

**開一個新的 terminal**，`start.sh` 那個不要關：

```bash
cd honeypot/layer3/frontend
npm install   # 第一次才需要
npm run dev        # 開啟 http://localhost:5173
```

> Dashboard 的資料來自 Stats API（port 8001）。`start.sh` 沒跑的話，頁面會是空的。

#### 6. Terminal 1 — 打蜜罐讓資料進來

服務跑起來後資料庫是空的，Dashboard 不會有任何顯示。在 terminal 1 攻擊一下讓資料進來：

```bash
ssh -p 2222 admin@localhost          # 密碼: admin
ssh -p 2222 root@localhost           # 密碼: toor
ssh -p 2222 dbadmin@localhost        # 密碼: Sup3rS3cr3t!2019
curl http://localhost:8080/wp-admin
./scripts/demo.sh                    # 自動化模擬攻擊（簡易版）
```

**全套攻擊模擬（推薦）** — 4 條攻擊鏈 + 13 個 phase，一鍵產生豐富的 Dashboard 資料：

```bash
cd honeypot
# 完整模擬（約需 5-10 分鐘，視 LLM 速度而定）
.venv/bin/python scripts/attack_full.py

# 只跑 4 條攻擊鏈（快速展示）
.venv/bin/python scripts/attack_full.py --chains-only

# 只跑指定鏈（A=WordPress滲透, B=系統接管, C=資料竊取, D=Web攻擊）
.venv/bin/python scripts/attack_full.py --chain A

# 只跑指定 phase（0-12）
.venv/bin/python scripts/attack_full.py --phase 9

# 外部目標
.venv/bin/python scripts/attack_full.py --host glows.ai-server --ssh-port 2222 --http-port 8080
```

攻擊完畢後重新整理 Dashboard，就會看到 Session 紀錄和圖表。

#### 查看完整指令與回應紀錄

每一筆 SSH 指令和 HTTP 請求（含 LLM 回應）都會存進 `honeypot.db`。攻擊模擬結束後，用以下腳本匯出完整紀錄：

```bash
cd honeypot

# 查看全部 session 的所有指令與回應
.venv/bin/python scripts/dump_responses.py

# 只看最近 3 個 session
.venv/bin/python scripts/dump_responses.py --last 3

# 只看 LLM 生成的回應（排除 cache，適合分析 LLM 品質）
.venv/bin/python scripts/dump_responses.py --llm-only

# 篩選特定攻擊意圖
.venv/bin/python scripts/dump_responses.py --intent privilege_escalation

# 儲存成文字檔（適合事後分析或交給 AI 審查）
.venv/bin/python scripts/dump_responses.py --out report.txt --no-colour
```

輸出格式：每筆紀錄顯示來源（cache / LLM）、意圖分類、信心分數、指令內容、完整回應。

---

### 方法 B：Docker（自己電腦才能用）

Ollama 需要能讓容器連到。macOS / Windows 上用 `host.docker.internal`：

```env
# honeypot/.env
OLLAMA_HOST=http://host.docker.internal:11434
```

啟動：
```bash
cd honeypot
docker compose up
```

Dashboard 同樣用 `npm run dev` 啟動，打開 http://localhost:5173。

---

## Dashboard 頁面

| 頁面 | 內容 |
|---|---|
| Dashboard | WebSocket 即時攻擊串流、意圖分佈圓餅圖、Top Commands 長條圖、Session 統計 |
| Sessions | 所有 Session 列表，點入可逐條重播每個指令與 LLM 回應 |
| Reports | 每個 Session 的 LLM 生成 Markdown 威脅情報報告（含 MITRE ATT&CK 標籤） |

---

## 詳細架構

### 檔案結構

```
honeypot/
  shared/
    models.py              # Pydantic 共用資料模型（RespondRequest/RespondResponse）
  layer1/
    ssh_server.py          # paramiko SSH 蜜罐
    http_server.py         # FastAPI WordPress 蜜罐
    session_manager.py     # Session 狀態（current_dir、history）
    llm_client.py          # 呼叫 Layer 2 的 HTTP client
    logger.py              # SQLite 寫入
  layer2/
    main.py                # FastAPI POST /respond
    cache.py               # 規則快取 + 假檔案系統
    intent_classifier.py   # 關鍵字意圖分類
    prompt_builder.py      # Ubuntu 18.04 人設 System Prompt
    ollama_client.py       # Ollama HTTP client，支援串流
    db.py                  # SQLite Schema + 連線管理
  layer3/
    stats_api.py           # 唯讀 FastAPI + WebSocket /ws/live
    report_generator.py    # LLM Markdown 報告生成
    frontend/              # React + Vite → Vercel
  honeypot.db              # 共用 SQLite 資料庫
  .env                     # 所有設定
  scripts/
    setup.sh               # 初次建置（venv、套件、Ollama 模型）
    start.sh               # 啟動後端四個服務
    start-all.sh           # 一鍵啟動後端 + 前端（tmux）
    update.sh              # git pull + 重啟服務
    demo.sh                # Demo 用模擬攻擊腳本
```

### Layer 1 → Layer 2 JSON 介面

```json
// 請求
{ "session_id": "abc123", "protocol": "ssh", "command": "cat /etc/passwd",
  "current_dir": "/etc", "user": "admin", "history": ["whoami", "ls"] }

// 回應
{ "session_id": "abc123", "response": "root:x:0:0...",
  "intent": "reconnaissance", "confidence": 0.95, "cache_hit": false }
```

### 切換模型

只需改 `.env`，不需動任何程式碼：
```env
# 終端回應模型（每個 SSH 指令）
OLLAMA_MODEL=llama3.1:8b-instruct-q8_0

# 報告生成模型（session 結束時）
OLLAMA_REPORT_MODEL=qwen2.5:14b-instruct-q4_K_M
```

### 調整 LLM 行為

以下參數視硬體和模型能力可自行調整：

| 參數 | 位置 | 預設值 | 說明 |
|------|------|--------|------|
| `num_ctx` | `layer2/ollama_client.py` | `8192` | Ollama context window。硬體不足可降至 `4096`；Ollama 本身預設只有 2048，不設定會導致 system prompt 被截斷 |
| `response[:500]` | `layer1/session_manager.py` | `500` 字元 | 每筆指令回應存入歷史的長度。過短會讓 LLM 忘記之前回傳的檔案內容 |
| `history_pairs` 上限 | `layer1/session_manager.py` | `20` 對 | Session 內最多保留幾組指令+回應。超過後滑動捨棄最舊的 |
| `history[-20:]` | `layer2/prompt_builder.py` | `20` 組 | 每次呼叫 LLM 時送入的歷史深度，應與上方保持一致 |

---

## Docker

```bash
cd honeypot
docker compose up
```

注意：Ollama 必須讓容器能連到。在 macOS 上請將 `.env` 的 `OLLAMA_HOST` 設為 `http://host.docker.internal:11434`。

---

## Vercel 部署（Dashboard）

1. 將 `OLLAMA_HOST` 設為可公開存取的 URL
2. 修改 `layer3/frontend/vercel.json` 填入 Stats API 的網址
3. 部署：`cd layer3/frontend && npx vercel --prod`

---

## 執行測試

glows.ai 和自己電腦都一樣：

```bash
cd honeypot
.venv/bin/pytest tests/ -v
```

38 個測試，涵蓋 SQLite Schema、Logger、Session Manager、規則快取、意圖分類器、Prompt Builder、FastAPI 端點、Stats API。不需要 Ollama 在跑，也不需要任何外部服務。
