# HoneyPot on glows.ai

> **⚠️ 前置條件：GitHub Repo 必須可存取**
>
> 此 repo 目前為 **Private**，在 glows.ai 上直接 `git clone` 會失敗。請先選擇以下其中一種方式：
>
> **方法 A（最省事）— 改成 Public：**
> HoneyPot repo → Settings → Danger Zone → Change visibility → Public
> `.env` 裡沒有真正的密碼，公開安全。
>
> **方法 B — Personal Access Token：**
> GitHub → Settings → Developer settings → Personal access tokens → 產生 token（勾 `repo`），clone 時用：
> ```bash
> git clone https://<your-token>@github.com/TAICA-oops/HoneyPot.git
> ```

glows.ai 已預裝 Ollama，使用三個腳本即可完成所有初始化和啟動：

| 腳本 | 用途 |
|------|------|
| `scripts/setup.sh` | **初次建置**：venv、套件、Ollama 模型、前端套件 |
| `scripts/start-all.sh` | **一鍵啟動**：後端 4 個服務 + 前端，tmux 持久執行 |
| `scripts/update.sh` | **更新**：git pull + 重裝套件 + 重啟服務 |

---

## 初次建置（只需執行一次）

### 1. Clone 專案

```bash
git clone https://github.com/TAICA-oops/HoneyPot.git
cd HoneyPot/honeypot
```

### 2. 一鍵初始化

```bash
bash scripts/setup.sh
```

這個腳本會自動做：
- 建立 Python 虛擬環境（`.venv/`）
- `pip install -e .`（安裝所有 Python 套件）
- `npm install`（安裝前端套件）
- 檢查 Ollama 是否運行，並自動下載缺少的模型：
  - `llama3.1:8b-instruct-q8_0`（終端回應，~8.5GB）
  - `qwen2.5:14b-instruct-q4_K_M`（威脅報告，~9GB）

> **模型下載時間**：兩個模型合計約 17GB，glows.ai 上首次下載可能需要 10–20 分鐘。之後再次執行 `setup.sh` 會自動跳過已存在的模型。

### 3. 確認 .env 設定

`honeypot/.env` 已有預設值，通常不需要修改：

```env
OLLAMA_MODEL=llama3.1:8b-instruct-q8_0
OLLAMA_REPORT_MODEL=qwen2.5:14b-instruct-q4_K_M
OLLAMA_HOST=http://localhost:11434
SSH_PORT=2222
HTTP_PORT=8080
LLM_ENGINE_PORT=8000
STATS_API_PORT=8001
DB_PATH=./honeypot.db
SESSION_TIMEOUT_SECONDS=600
```

---

## 啟動所有服務

```bash
bash scripts/start-all.sh
```

這個腳本會用 **tmux** 同時啟動：

| Window | 服務 | Port |
|--------|------|------|
| `backend` | Layer 2 LLM、Layer 3 Stats API、Layer 1 SSH、Layer 1 HTTP | 8000、8001、2222、8080 |
| `frontend` | React Dashboard（Vite dev server） | 5173 |

> **為什麼用 tmux？** terminal 關掉後服務繼續跑。沒有 tmux 時會自動改用 `nohup`。

### Port Forwarding（在 glows.ai 介面設定）

| Port | 用途 |
|------|------|
| **5173** | Dashboard 前端（必要，用瀏覽器開） |
| **2222** | SSH 蜜罐（可選，想從外部 SSH 進來時） |
| **8080** | HTTP 蜜罐（可選，想從外部打 HTTP 時） |

8000（LLM）和 8001（API）是內部服務，不需要對外開放。

### tmux 操作

```bash
tmux attach -t honeypot              # 進入 tmux（預設看 backend）
tmux attach -t honeypot:backend      # 看後端 log
tmux attach -t honeypot:frontend     # 看前端 log
tmux kill-session -t honeypot        # 停止所有服務
```

進入 tmux 後：
- `Ctrl+B, D` — detach（離開但保持服務運行）
- `Ctrl+B, N` / `Ctrl+B, P` — 切換 window

---

## 確認服務正常

```bash
curl http://localhost:8000/health        # 應回傳 {"status":"ok"}
curl http://localhost:8001/api/sessions  # 應回傳 []
```

---

## 打蜜罐讓資料進來

```bash
# SSH（需使用弱密碼）
ssh -p 2222 admin@localhost       # 密碼: admin
ssh -p 2222 root@localhost        # 密碼: toor
ssh -p 2222 dbadmin@localhost     # 密碼: Sup3rS3cr3t!2019

# HTTP
curl http://localhost:8080/wp-login.php
curl http://localhost:8080/.env

# 自動化 demo（需要 sshpass）
# 安裝：sudo apt install -y sshpass
bash scripts/demo.sh
```

---

## 更新（之後每次改 code 後）

```bash
bash scripts/update.sh
```

自動執行：`git pull origin main` → `pip install -e .` → `npm install` → 重啟後端和前端服務。

---

## 執行測試

```bash
cd honeypot
.venv/bin/pytest tests/ -v
```

38 個測試，不需要 Ollama 在跑。

---

## 常見問題

**Q: `setup.sh` 說 Ollama 未執行怎麼辦？**
A: 在 glows.ai 上 Ollama 應已預裝。如果沒有跑，嘗試重新整理頁面或確認工作環境已啟動。之後單獨執行模型下載：
```bash
ollama pull llama3.1:8b-instruct-q8_0
ollama pull qwen2.5:14b-instruct-q4_K_M
```

**Q: Port 5173 Dashboard 打開是空白？**
A: 確認後端已啟動（`curl http://localhost:8001/api/sessions` 有回應），且 glows.ai Port Forwarding 有加 5173。

**Q: SSH 連線被拒絕？**
A: 蜜罐只接受弱密碼，請用 `admin/admin`、`root/toor` 等帳密。
