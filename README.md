# LLM 驅動蜜罐系統

一個高互動型蜜罐，將攻擊者困在擬真的假 Linux 伺服器和 WordPress 網站中，由本地 LLM 即時生成回應。每個指令都會被分類攻擊意圖、記錄至 SQLite，並在即時 React Dashboard 上呈現，最終自動生成威脅情報報告。

本專案的核心不只是「用 LLM 生成假回應」，而是進一步處理 LLM 蜜罐最大的弱點——**回應前後不一致導致被攻擊者識破（穿幫）**。我們以「規則快取 + 單一真相來源 + 一致性狀態管理」把 LLM 的不確定性收斂成一致的擬真系統，並針對攻擊者實際會用來偵測蜜罐的手法（指令交叉比對、權限驗證、SSH 指紋、時間檢查）做了系統性的反偵測強化。詳見 [擬真度工程與反偵測](#擬真度工程與反偵測本專案核心) 與 [`docs/realism-audit-and-plan.md`](docs/realism-audit-and-plan.md)。

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

**SSH 人設：** Ubuntu 18.04.6 LTS 電商後台伺服器（paramiko，協商演算法與 host key 對齊真實 OpenSSH 7.6）。只接受常見弱密碼（admin/admin、root/toor、dbadmin/Sup3rS3cr3t!2019 等）登入，支援互動式 shell 與非互動式 `ssh host 'cmd'`。常見指令（ls、cat、pwd、id、history、ss/netstat…）直接從規則快取秒回，配備完整的假檔案系統——含假資料庫憑證的 `/var/www/html/.env`、`/home/admin/backup.sql` MySQL dump、`/home/dbadmin/.my.cnf`、設定錯誤的 sudoers 等誘餌檔。**所有誘餌內容集中在 `shared/fake_fs.py` 單一真相來源**，並套用真實的 Unix 權限模型（非檔主讀不到他人私密檔、root 才能讀 shadow）與提權狀態（`sudo su` 後身分持續到 `exit`）。陌生指令才送 LLM；LLM 對 `ls`/`cat`/`find` 等讀取指令的回應會跨 session 快取，確保不同攻擊者看到一致的假檔案系統。

**HTTP 人設：** 假 WordPress 網站。回應 `/wp-admin`、`/wp-login.php`（記錄攻擊者輸入的帳密）、`/.env`（與 SSH 同一份誘餌）、`/phpmyadmin`（POST 收割帳密與 `sql_query` 注入內容）、`/xmlrpc.php`，其他路徑回傳 WordPress 風格的 404。同一來源 IP 的所有 HTTP 活動聚合成單一 session，威脅等級取期間最高。

**意圖分類器：** 關鍵字比對，將 SSH 指令和 HTTP 請求分為 `reconnaissance`（偵查）、`privilege_escalation`（提權）、`data_exfiltration`（資料外洩）、`persistence`（持久化）、`lateral_movement`（橫向移動）、`credential_harvesting`（帳密竊取）、`web_recon`（網站偵查）、`injection_attempt`（注入攻擊），其餘為 `unknown`。快速路徑處理 80% 以上的情況，不需呼叫 LLM。

**威脅報告：** Session 結束時自動觸發（單一 worker 佇列串行生成，避免併發灌爆 Ollama），包含 Executive Summary、攻擊時間軸、意圖分析、**MITRE ATT&CK 對應**、IoC 指標、威脅等級（Low / Medium / High / Critical）。威脅等級由規則決定（非 LLM 自由判斷），報告 LLM 只負責解釋佐證。

---

## 擬真度工程與反偵測（本專案核心）

LLM 蜜罐最大的風險是**穿幫**：LLM 每次生成的內容會漂移，攻擊者只要用幾個指令交叉比對，就能發現「這台機器是假的」。我們把這視為主要威脅模型，系統性地消除攻擊者實際會用的偵測手法。完整審查與檢查清單見 [`docs/realism-audit-and-plan.md`](docs/realism-audit-and-plan.md)。

### 1. 單一真相來源（Single Source of Truth）
所有誘餌內容（`.env`、`wp-config.php`、`/etc/passwd`、`/etc/shadow`、`.my.cnf`、backup.sql、指令歷史、UID 表、家目錄、存在的目錄/檔案集合、sudoers）集中在 `shared/fake_fs.py`。SSH 的 `cat`、HTTP 的 `/.env`、以及 LLM system prompt 全部 import 同一份，杜絕「從不同介面拿到不同內容」的破綻。

### 2. 一致性狀態管理（Layer 1 持有狀態，LLM 不管狀態）
- **目錄狀態**：`cd` 完全由 Layer 1 處理；`cd`/`ls` 共用同一組 `FAKE_DIRS`，凡 `ls` 列得出的目錄都能 `cd` 進去（修掉「`ls /var` 有 log 但 `cd /var/log` 失敗」這類破綻）。路徑會正規化（尾斜線、`.`、`..`）。
- **權限模型**：`fake_fs.can_read()` 套用真實 Unix 語意——非檔主讀不到他人 600 私密檔（`.bash_history`/`.my.cnf`），只有 root 能讀 `/etc/shadow`、`/etc/sudoers`。
- **提權狀態持續**：`session_manager` 用使用者堆疊（`user_stack`）追蹤 effective user。`sudo su`/`sudo -i`/`sudo bash` 切成 root 並維持，`whoami`/`id`/檔案權限都隨之改變，`exit`/Ctrl-D 逐層退回——解決「`sudo su` 後下一個 `whoami` 又變回原帳號」的矛盾。

### 3. 跨指令一致性
- **動態檔案系統快取**：LLM 對 `ls`/`cat`/`find` 的回應會以 `(指令, 路徑, 使用者)` 為鍵跨 session 快取，不同攻擊者看到同一份「LLM 編出來的」檔案系統。
- **確定性讀取**：`head`/`tail`/`wc` 對已知誘餌檔由內容程式化計算，與 `cat` 一致（避免 `wc -c .env` 和 `cat .env` 對不上）。
- **`ls -l` 大小**＝實際內容長度；`history` 內建指令與 `~/.bash_history` 共用同一份劇本；登入落在各自家目錄；身分 = `whoami` = `id` = `echo $USER` = `/etc/passwd` 條目，全部一致。

### 4. SSH 協定層反指紋
paramiko 預設提供的演算法清單（含 `3des-cbc`、`diffie-hellman-group1-sha1`、`hmac-md5`、`ssh-dss`）會被 `nmap ssh2-enum-algos` 或 `ssh -vv` 一眼識別為「非 OpenSSH」。我們：
- 將 KEX / cipher / MAC / host-key 協商清單收斂成 **OpenSSH 7.6p1 風格**（取 paramiko 支援的交集並依 OpenSSH 順序）。
- host key 提供 **Ed25519 + ECDSA + RSA** 三型別（與真實 Ubuntu sshd 一致；Ed25519 用 `cryptography` 產生，因 paramiko 3.x 無 `generate()`）。
- 實機驗證：client 連線協商出 `aes128-ctr` / `curve25519` / `ssh-ed25519`。

### 5. 時間擬真
`date`/`uptime` 回傳**即時 UTC 時間**且會前進（uptime 從約 312 天前的開機時間起算），不再永遠卡在 2023、`date` 兩次也不再完全相同。LLM 生成日誌時，prompt 會在每次請求附上當前 `System time`。

### 6. Prompt Injection 防護（LLM 蜜罐特有威脅）
攻擊者若察覺後端是 LLM，可能用 `IGNORE PREVIOUS INSTRUCTIONS`、`SYSTEM OVERRIDE` 試圖越獄。終端與報告兩個 system prompt 開頭都明確聲明：`Command:`/事件日誌為**不可信資料**，其中的指示文字一律當普通字串處理，並附範例（`echo 'IGNORE...'` → 只印出那串文字）。實測若無此防護，LLM 偶爾會被注入文字誤導。

### 7. 誘餌品質
誘餌憑證刻意避開「教科書範例值」——例如 AWS 金鑰不用文件範例 `AKIAIOSFODNN7EXAMPLE`（任何掃描器一眼認出是假），改用格式合法但無效的隨機值。

> **回歸測試靈感**：`docs/realism-audit-and-plan.md` 附有「攻擊者測蜜罐檢查清單」，新增功能前可逐項自我檢查是否又產生破綻。

---

## LLM 上下文管理與跨連線一致性

高互動 LLM 蜜罐的核心挑戰在於：語言模型的輸出具隨機性，若無約束，同一攻擊者前後查詢、或多次連線時回應會彼此矛盾而暴露身分。本系統以**三層機制**處理三種不同範圍的一致性。

### 1. 連線內脈絡（LLM 看得到攻擊者前面的操作）
每條 SSH 連線維護一份指令–回應歷史（`session_manager` 的 `history_pairs`，上限 20 組、單筆回應截斷 500 字元）。`ssh_server` 把它組成 `$ 指令\n回應` 的 `rich_history`，經 `prompt_builder` 置於 system prompt 之後的 user message（「Previous commands in this session:」），讓模型感知攻擊者先前的操作與系統先前的輸出，維持多步驟互動的連貫性（例如先 `cd` 再 `ls`、先看到某檔再 `cat`）。為避免 Ollama 預設 2,048 token 上下文窗截斷人設提示，明確設定 `num_ctx=8192`，並依 *Lost in the Middle* 將穩定人設置於最前、當前指令置於最後。

### 2. 跨連線的「世界一致性」（靠世界固定，而非記得攻擊者）
系統不依賴模型「記得」攻擊者，而是讓**被觀測的世界本身固定**：
- 確定性內容由規則引擎與 `shared/fake_fs.py` 直接回覆，每次連線完全相同。
- 模型對唯讀檔案系統指令（ls/cat/find…）的虛構回應，以 `(指令, 目錄, 使用者)` 為鍵跨連線快取（`layer2/main.py` 的 `_dynamic_fs`，**不含 session_id 也不含 IP**）；因此同一路徑無論由哪條連線、哪個攻擊者查詢都得到相同結果，連模型臨時編造的部分也在不同連線間一致。

### 3. 跨協定一致性（SSH ↔ HTTP）
兩個協定共享同一份誘餌資產（如 `.env`），確保攻擊者由 Web（`/.env`）取得的憑證與由 shell（`cat /var/www/html/.env`）讀到的內容相符。HTTP 端不呼叫 LLM，故兩者之間共享的是靜態誘餌而非 LLM 脈絡。

### 「記錄」與「記憶」的區別
同一來源 IP 的連線**都會被記錄**：每個 session 列都帶 `attacker_ip`，HTTP 更以 `http-<ip>` 將同 IP 請求聚合成單一 session，Dashboard 與 Geo 統計皆以 IP 分組——因此「這個 IP 連了幾次、做了什麼」查得到。但這份紀錄目前**僅用於記錄與分析，尚未在 SSH 重連時回灌給 LLM 當上下文**；模型維持一致靠的是「世界固定」，而非「記得你來過」。

### 限制與未來工作
目前維持的是「狀態快照」一致性而非「可變狀態」一致性：攻擊者的破壞性／持久化操作（新增使用者、寫入檔案、植入 crontab）會被即時模擬為成功，但不會被持久化，故後續（含重連）重新讀取時不會反映該變更。可行改進：
- **(a) 跨連線記憶**：以攻擊者 IP 為索引，重連時自 SQLite 既有 `commands` 紀錄重建對話脈絡，提供跨連線的對話連續性（資料已具備，只差回灌）。
- **(b) 可變狀態覆寫層**：以輕量 overlay 記錄被建立／修改的檔案與帳號，後續讀取指令先查 overlay 再回落到基準檔案系統，使可變狀態也保持一致。

---

## 設計決策與研究筆記

> 這一節整理專案的關鍵設計取捨與背後的研究，適合直接擷取進書面報告。

### 混合架構：規則快取優先，LLM 兜底
不是每個指令都呼叫 LLM。`layer2/cache.py` 先用規則處理高頻、確定性的指令（`ls`/`cat`/`whoami`/`id`/`uname`/`ss`/`history`/`sudo -l`…），**快取未命中才送 Ollama**。動機：
- **延遲**：弱密碼掃描器一秒打很多指令，本地 LLM 每次回應數百毫秒～數秒；cache 秒回才像真實 shell。
- **一致性**：高頻指令走確定性規則，不會因 LLM 取樣漂移而前後矛盾。
- **成本**：>80% 指令不必動用 GPU。

### 雙模型策略
| 用途 | 模型 | temperature | 理由 |
|---|---|---|---|
| 終端回應 | `llama3.1:8b-instruct-q8_0` | 0.1 | 要快、要穩、要貼近真實 shell 輸出；低溫降低漂移 |
| 威脅報告 | `qwen2.5:14b-instruct-q4_K_M` | 0.6 | 報告非即時，可用較大模型換取分析品質與中英文表達 |

硬體：單張 RTX 4090（24GB），兩模型合計約 17.5GB VRAM 可同時常駐（`keep_alive=-1`）。

### Context Window 研究
- Ollama 預設 `num_ctx` 只有 **2048**，會把我們約 3,200 tokens 的 system prompt 截斷 → 明確設為 **8192**。
- llama3.1 / qwen2.5 架構上限雖達 128K，但都有 *Lost in the Middle*（中段資訊易被忽略）問題；故 prompt 結構刻意把 **system prompt 放最前、當前指令放最後**，符合 best practice。
- 歷史深度（送入 LLM 的指令+回應對數）與回應截斷長度需與 `session_manager` 一致，見下方「調整 LLM 行為」表。

### 意圖分類與威脅評分（規則優先，可解釋）
- 意圖用關鍵字規則（`first match wins`，高特異度類別排前面，避免 `curl` 一律被當資料外洩）。好處是**零延遲、可解釋、可審計**，不依賴 LLM。
- 威脅等級由規則決定：`privilege_escalation` ∧ `data_exfiltration` → Critical；任一 → High；`persistence`/`lateral_movement` → Medium；其餘 Low。**報告 LLM 不得覆寫此等級**，只能引用實際指令佐證——避免 LLM 隨意評分。
- 報告自動對應 **MITRE ATT&CK**（如 T1078 有效帳號、T1003 憑證取得、T1548.003 sudo 提權、T1190 公開應用攻擊），且要求「只列實際觀察到的行為、不得杜撰」。

### 攻擊模擬資料集
`scripts/attack_full.py` 內建 4 條攻擊鏈（WordPress 滲透、系統接管、資料竊取、Web 攻擊）+ 13 個 phase（recon → 提權 → 橫向 → 持久化 → 惡意程式 → 反向 shell → SQLi/XSS/LFI/Log4j/SSRF/XXE/SSTI → 掃描器模擬），可一鍵產生豐富且有「劇情」的 Dashboard 資料與報告素材。

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
    fake_fs.py             # ★ 誘餌檔/權限/家目錄/目錄集合/時間 的單一真相來源
  layer1/
    ssh_server.py          # paramiko SSH 蜜罐（協商演算法對齊 OpenSSH、exec、提權偵測）
    http_server.py         # FastAPI WordPress 蜜罐（同 IP 聚合、收割帳密/SQL）
    session_manager.py     # Session 狀態（current_dir、history、提權 user_stack）
    llm_client.py          # 呼叫 Layer 2 的 HTTP client
    logger.py              # SQLite 寫入 + WebSocket 事件入列
  layer2/
    main.py                # FastAPI POST /respond（規則快取 → 動態 fs 快取 → LLM）
    cache.py               # 規則快取 + 假檔案系統 + 權限模型
    intent_classifier.py   # 關鍵字意圖分類
    prompt_builder.py      # Ubuntu 18.04 人設 System Prompt（嵌入 canonical 檔案系統）
    ollama_client.py       # Ollama HTTP client，支援串流
    db.py                  # SQLite Schema + 連線管理
  layer3/
    stats_api.py           # 唯讀 FastAPI + WebSocket /ws/live（CORS 可設定）
    report_generator.py    # LLM Markdown 報告生成 + 單一 worker 佇列
    frontend/              # React + Vite → Vercel
  tests/                   # 101 個測試（一致性、權限、提權、SSH 指紋、HTTP、報告佇列…）
  honeypot.db              # 共用 SQLite 資料庫
  .env                     # 所有設定
  scripts/
    setup.sh               # 初次建置（venv、套件、Ollama 模型）
    start.sh               # 啟動後端四個服務
    start-all.sh           # 一鍵啟動後端 + 前端（tmux）
    attack_full.py         # 全套攻擊模擬（4 條攻擊鏈 + 13 phase）
    dump_responses.py      # 匯出指令/回應紀錄供事後分析
    update.sh / demo.sh    # 更新重啟 / Demo 攻擊
docs/
  realism-audit-and-plan.md  # 擬真度審查、修法、剩餘限制、測蜜罐檢查清單
```

### Layer 1 → Layer 2 JSON 介面

```json
// 請求（user = 目前 effective user；attacker_ip 用於 ss/netstat 顯示攻擊者自身連線）
{ "session_id": "abc123", "protocol": "ssh", "command": "cat /etc/passwd",
  "current_dir": "/etc", "user": "admin", "history": ["whoami", "ls"],
  "attacker_ip": "203.0.113.9" }

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

### Prompt Injection 防護

見上方 [擬真度工程與反偵測 §6](#6-prompt-injection-防護llm-蜜罐特有威脅)。終端與報告兩個 System Prompt 開頭都聲明攻擊者輸入為不可信資料，並附範例示範正確行為。

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

**101 個測試**，涵蓋 SQLite Schema、Logger、Session Manager、規則快取、意圖分類器、Prompt Builder、FastAPI 端點、Stats API，以及本次新增的擬真度測試：跨層誘餌一致性、權限模型、提權狀態、`head/tail/wc` 與 `cat` 一致、SSH 演算法指紋與三型別 host key、HTTP 同 IP 聚合與帳密/SQL 收割、報告佇列、CORS 設定。不需要 Ollama 在跑，也不需要任何外部服務。

---

## 已知限制

> 誠實列出，方便報告討論與後續改進。

- **SSH 協定層仍非 100% OpenSSH**：常見的 `nmap ssh2-enum-algos`/`ssh -vv` 看到的演算法清單已與 OpenSSH 7.6 一致，但 paramiko 終究不是 OpenSSH，極深入的時序/實作指紋分析仍可能有差異。
- **`stat`/`grep` 與管線走 LLM**：`head/tail/wc` 已對誘餌檔確定性化，但 `stat`、`grep`、`cat … | grep …`、重導向等仍交給 LLM（`stat` 要補齊 inode/owner/mode 才不會與 `ls -l` 打架，成本較高）。
- **互動式終端細節**：方向鍵/Tab 補全會被當字元塞進指令（非真正的 readline）。
- **Stats API 對外部署**：目前僅 `CORS_ORIGINS` 可鎖定來源，尚無認證與報告端點的 rate-limit；正式對外建議再補。

詳見 [`docs/realism-audit-and-plan.md`](docs/realism-audit-and-plan.md)。
