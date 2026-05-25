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

**SSH 人設：** Ubuntu 18.04.6 LTS 電商後台伺服器。任何帳號密碼都能登入。常見指令（ls、cat、pwd）直接從規則快取秒回，配備完整的假檔案系統——包含假資料庫憑證的 `/var/www/html/.env`、`/home/admin/backup.sql` MySQL dump，以及設定錯誤的 sudoers 等誘餌檔案。陌生指令才送 LLM 生成回應。

**HTTP 人設：** 假 WordPress 網站。回應 `/wp-admin`、`/wp-login.php`（記錄攻擊者輸入的帳密）、`/.env`（誘餌檔）、`/phpmyadmin`、`/xmlrpc.php`，其他路徑回傳 WordPress 風格的 404。

**意圖分類器：** 關鍵字比對，將指令分為 `reconnaissance`（偵查）、`privilege_escalation`（提權）、`data_exfiltration`（資料外洩）、`persistence`（持久化）、`lateral_movement`（橫向移動）。快速路徑處理 80% 以上的情況，不需呼叫 LLM。

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

glows.ai 上 Ollama 已經在跑，直接用 `start.sh` 即可，**不需要 Docker**。

### 1. 安裝 Python 套件

```bash
cd honeypot
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 確認 Ollama 模型

```bash
ollama list                  # 確認有哪些模型
ollama pull llama3.1         # 沒有的話先拉取
```

### 3. 設定

編輯 `honeypot/.env`，`OLLAMA_HOST` 保持 localhost：

```env
OLLAMA_MODEL=llama3.1
OLLAMA_HOST=http://localhost:11434
SSH_PORT=2222
HTTP_PORT=8080
LLM_ENGINE_PORT=8000
STATS_API_PORT=8001
DB_PATH=./honeypot.db
SESSION_TIMEOUT_SECONDS=600
```

### 4. Terminal 1 — 啟動後端所有服務

```bash
cd honeypot
./scripts/start.sh
```

Layer 2（LLM 引擎）、Layer 3（Stats API）、Layer 1 SSH、Layer 1 HTTP 全部在背景啟動。**這個 terminal 要一直開著**，按 `Ctrl+C` 全部停止。

確認服務正常：
```bash
curl http://localhost:8000/health        # 應回傳 {"status":"ok"}
curl http://localhost:8001/api/sessions  # 應回傳 []
```

### 5. Terminal 2 — 啟動 Dashboard 前端

**開一個新的 terminal**，`start.sh` 那個不要關：

```bash
cd honeypot/layer3/frontend
npm install   # 第一次才需要
npm run dev
```

接著在 glows.ai 介面的 Port Forwarding 設定加入 port `5173`，用瀏覽器開對應的 URL。

> Dashboard 的資料來自 Stats API（port 8001）。`start.sh` 沒跑的話，頁面會是空的。

### 6. Terminal 1 — 打蜜罐讓資料進來

服務跑起來後資料庫是空的，Dashboard 不會有任何顯示。在 terminal 1 攻擊一下讓資料進來：

```bash
# SSH（任何帳密都能登入，亂打都行）
ssh -p 2222 anyuser@localhost

# 或直接跑自動化 demo 攻擊
./scripts/demo.sh
```

攻擊完畢後重新整理 Dashboard，就會看到 Session 紀錄和圖表。

---

## 在自己電腦上啟動

### 方法 A：直接用 start.sh

#### 1. 安裝 Ollama

至 [ollama.ai](https://ollama.ai) 下載安裝，然後：

```bash
ollama pull llama3.1
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
ssh -p 2222 anyuser@localhost      # 任何帳密
curl http://localhost:8080/wp-admin
./scripts/demo.sh                  # 自動化模擬攻擊
```

攻擊完畢後重新整理 Dashboard，就會看到 Session 紀錄和圖表。

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
| Dashboard | WebSocket 即時攻擊串流、意圖分佈圓餅圖、Session 統計 |
| Sessions | 所有 Session 列表，點入可逐條重播每個指令與 LLM 回應 |
| Reports | 每個 Session 的 LLM 生成 Markdown 威脅情報報告 |

---

## 詳細架構

### 檔案結構

```
honeypot/
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
    start.sh               # 本機啟動所有服務
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

只需改 `.env` 一行，不需動任何程式碼：
```env
OLLAMA_MODEL=gemma3        # 或 mistral、phi4、deepseek-r1 等
```

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

34 個測試，涵蓋 SQLite Schema、Logger、Session Manager、規則快取、意圖分類器、Prompt Builder、FastAPI 端點、Stats API。不需要 Ollama 在跑，也不需要任何外部服務。
