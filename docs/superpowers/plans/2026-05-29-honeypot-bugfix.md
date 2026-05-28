# HoneyPot Bug Fix Plan（Codex 審查後）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修復 Codex 審查發現的 14 個 bug，涵蓋 shared models、SSH server 邏輯、HTTP server、WebSocket 架構、Layer 3 API 安全性、前端 UX，以及更新 README / CLAUDE.md 文件。

**Architecture:** 所有修改在 `feature/phase2-improvements` 分支上進行。WebSocket 跨 loop 問題以 thread-safe queue 解決（logger 推事件進 queue，FastAPI 的 ASGI loop 消費）。其餘 bug 為獨立的小修正，不影響整體架構。

**Tech Stack:** Python 3.11, FastAPI, paramiko, asyncio, React 18 + TypeScript + Recharts

---

## File Map

```
honeypot/
  shared/models.py              ← Task 1：補 VALID_INTENTS
  layer1/
    ssh_server.py               ← Task 2：cd bug、session_end 保障、history_pairs
    http_server.py              ← Task 3：session_id collision、phpMyAdmin POST
    logger.py                   ← Task 4：移除自建 loop，改用 enqueue_event
  layer2/
    db.py                       ← Task 7：WAL mode + indexes
  layer3/
    stats_api.py                ← Task 4：queue consumer + WebSocket set + lock；Task 5：404、/api/config
    report_generator.py         ← Task 5：Ollama 失敗檢查
    frontend/src/
      components/
        CommandChart.tsx         ← Task 6：loading/error state
        IntentChart.tsx          ← Task 6：改 ResponsiveContainer
        LiveFeed.tsx             ← Task 6：reconnect + wss
README.md                       ← Task 8
CLAUDE.md                       ← Task 8
```

---

## Task 1：修復 VALID_INTENTS（B1，嚴重性：高）

**Files:**
- Modify: `honeypot/shared/models.py`

**問題：** `intent_classifier.py` 新增了 `credential_harvesting`、`web_recon`、`injection_attempt`，但 `shared/models.py` 的 `VALID_INTENTS` 沒有同步更新，觸發這三種意圖時 `/respond` 會 500。

- [ ] **Step 1: 確認問題存在**

```bash
cd honeypot && python -c "
from shared.models import RespondResponse
try:
    RespondResponse(session_id='x', response='y', intent='web_recon', confidence=0.9, cache_hit=False)
    print('BUG NOT PRESENT')
except Exception as e:
    print('BUG CONFIRMED:', e)
"
```
Expected: `BUG CONFIRMED: intent must be one of ...`

- [ ] **Step 2: 修改 `honeypot/shared/models.py`，把 `VALID_INTENTS` 補齊**

```python
VALID_INTENTS = {
    "reconnaissance",
    "privilege_escalation",
    "data_exfiltration",
    "persistence",
    "lateral_movement",
    "credential_harvesting",
    "web_recon",
    "injection_attempt",
    "unknown",
}
```

- [ ] **Step 3: 驗證修正**

```bash
cd honeypot && python -c "
from shared.models import RespondResponse
r = RespondResponse(session_id='x', response='y', intent='web_recon', confidence=0.9, cache_hit=False)
print('OK:', r.intent)
"
```
Expected: `OK: web_recon`

- [ ] **Step 4: 跑完整測試**

```bash
cd honeypot && .venv/bin/pytest tests/ -v
```
Expected: 34 passed

- [ ] **Step 5: Commit**

```bash
git add honeypot/shared/models.py
git commit -m "fix(shared): 補上三種 HTTP 意圖到 VALID_INTENTS，避免 /respond 500"
```

---

## Task 2：SSH server 三個 bug（B3、B4、B7）

**Files:**
- Modify: `honeypot/layer1/ssh_server.py`

**B7:** `command.startswith("cd")` 會誤判 `cdx`、`cdsomething`
**B4:** `history_pairs` 有被存但沒有傳給 LLM（ssh_server 仍傳舊的 `history` list[str]）
**B3:** `session_end()` 在 exception 路徑沒有保障，`SessionManager.delete()` 從未被呼叫

- [ ] **Step 1: 修改 `_handle_client` 函式，加入 `_end_session` helper + finally 保障**

找到整個 `_handle_client` 函式，在函式開頭（`try:` 之前）加入 helper，並用 finally 保障清理：

```python
def _handle_client(sock: socket.socket, addr: tuple, logger: Logger) -> None:
    transport = None
    session_id = None
    _session_ended = False

    def _end_session():
        nonlocal _session_ended
        if session_id and not _session_ended:
            _session_ended = True
            try:
                level = _compute_threat_level(session_id)
                logger.session_end(session_id, level)
                _auto_generate_report(session_id)
            except Exception as e:
                print(f"[ssh] session cleanup error: {e}")
        if session_id:
            _SESSION_MGR.delete(session_id)

    try:
        transport = paramiko.Transport(sock)
        # ... （中間邏輯不變）
```

然後把原本所有 `logger.session_end(session_id, _compute_threat_level(session_id))` 和 `_auto_generate_report(session_id)` 的呼叫，全部替換成 `_end_session()`。

在函式最後加入：

```python
    except Exception as e:
        print(f"[ssh] connection error {addr}: {e}")
    finally:
        _end_session()
        if transport:
            try:
                transport.close()
            except Exception:
                pass
```

- [ ] **Step 2: 修正 cd 判斷（B7）**

找到：
```python
            if command.startswith("cd"):
```
改成：
```python
            if command == "cd" or command.startswith("cd "):
```

- [ ] **Step 3: 修正 history_pairs 傳給 LLM（B4）**

找到這段（在 `else:` 分支裡）：

```python
                result = llm_client.respond(
                    session_id=session_id,
                    protocol="ssh",
                    command=command,
                    current_dir=_SESSION_MGR.get(session_id)["current_dir"],
                    user=server.username,
                    history=_SESSION_MGR.get(session_id)["history"],
                )
```

改成（把 history_pairs 序列化成 rich 字串傳給 LLM）：

```python
                session_data = _SESSION_MGR.get(session_id)
                # 把 history_pairs 格式化成 "$ cmd\nresponse" 字串
                rich_history = [
                    f"$ {cmd}\n{resp}" if resp.strip() else f"$ {cmd}"
                    for cmd, resp in session_data["history_pairs"]
                ] or session_data["history"]

                result = llm_client.respond(
                    session_id=session_id,
                    protocol="ssh",
                    command=command,
                    current_dir=session_data["current_dir"],
                    user=server.username,
                    history=rich_history,
                )
```

- [ ] **Step 4: 語法驗證**

```bash
cd honeypot && python -c "import layer1.ssh_server; print('OK')"
```
Expected: `OK`

- [ ] **Step 5: 跑測試**

```bash
cd honeypot && .venv/bin/pytest tests/ -v
```
Expected: 34 passed

- [ ] **Step 6: Commit**

```bash
git add honeypot/layer1/ssh_server.py
git commit -m "fix(layer1): cd 誤判、session_end finally 保障、history_pairs 傳給 LLM"
```

---

## Task 3：HTTP server 兩個 bug（B5、B6）

**Files:**
- Modify: `honeypot/layer1/http_server.py`

**B5:** session_id 碰撞（同 IP 同秒）；HTTP session 的 end_time 永不更新
**B6:** phpMyAdmin 缺少 POST handler

- [ ] **Step 1: 修正 `_make_session_id`（B5）**

在 import 區段確認有 `import uuid`（如果沒有就加），然後找到：

```python
def _make_session_id(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"http-{ip}-{int(time.time())}"
```

改成：

```python
def _make_session_id(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"http-{ip}-{uuid.uuid4().hex[:8]}"
```

- [ ] **Step 2: 在 `_log` 加入 session_end（B5）**

找到 `_log` 函式，在最後加入：

```python
def _log(request: Request, path: str, body: str, code: int, creds: str | None = None):
    sid = _make_session_id(request)
    attacker_ip = request.client.host if request.client else "unknown"
    _logger.session_start(sid, "http", attacker_ip)
    _logger.http_request(sid, request.method, path, body, code, creds)
    intent, conf = _classify_intent(path + " " + body)
    if intent != "unknown":
        _logger.command(sid, f"HTTP {request.method} {path}", "", intent, conf, True)
    # HTTP session 每次請求就完整記錄，立即結束
    from layer1.ssh_server import _compute_threat_level as _unused  # noqa
    threat = "High" if intent in ("credential_harvesting", "injection_attempt") else \
             "Medium" if intent in ("web_recon",) else "Low"
    _logger.session_end(sid, threat)
```

- [ ] **Step 3: 補 phpMyAdmin POST handler（B6）**

在 `async def phpmyadmin(request: Request):` 之後，加入：

```python
@app.post("/phpmyadmin", response_class=HTMLResponse)
@app.post("/phpmyadmin/", response_class=HTMLResponse)
async def phpmyadmin_post(
    request: Request,
    pma_username: str = Form(""),
    pma_password: str = Form(""),
):
    import json as _json
    creds = _json.dumps({"username": pma_username, "password": pma_password})
    _log(request, request.url.path,
         f"pma_username={pma_username}&pma_password={pma_password}", 200, creds)
    return HTMLResponse(_PHPMYADMIN_HTML, status_code=200)
```

- [ ] **Step 4: 語法驗證**

```bash
cd honeypot && python -c "import layer1.http_server; print('OK')"
```
Expected: `OK`

- [ ] **Step 5: 跑測試**

```bash
cd honeypot && .venv/bin/pytest tests/ -v
```
Expected: 34 passed

- [ ] **Step 6: Commit**

```bash
git add honeypot/layer1/http_server.py
git commit -m "fix(layer1): HTTP session_id 碰撞修正、HTTP session_end、補 phpMyAdmin POST handler"
```

---

## Task 4：WebSocket 架構修正（B2、B10）

**Files:**
- Modify: `honeypot/layer3/stats_api.py`
- Modify: `honeypot/layer1/logger.py`

**B2:** logger 用自己的 asyncio loop 呼叫 broadcast()，但 WebSocket 物件屬於 FastAPI 的 ASGI loop，跨 loop 操作不安全
**B10:** WebSocket client list 有 race condition（同一個 ws 被移除兩次 → ValueError）

**解法：** 引入 `queue.SimpleQueue`。logger 只做 `put_nowait(event)`（純同步），FastAPI 啟動一個 background task 在自己的 ASGI loop 消費 queue 並廣播。同時把 `_ws_clients` 改為 set + asyncio.Lock。

- [ ] **Step 1: 修改 `honeypot/layer3/stats_api.py`**

完整替換 WebSocket 相關程式碼（找到 `_ws_clients` 的定義及 `ws_live`、`broadcast` 函式，全部替換）：

```python
import os
import asyncio
import json
import queue as _queue
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
from layer2.db import get_conn

load_dotenv()

# Thread-safe event queue：logger 往這裡放事件（同步），ASGI loop 消費
_event_queue: _queue.SimpleQueue = _queue.SimpleQueue()

# WebSocket clients：改用 set + asyncio.Lock 避免 race condition
_ws_clients: set[WebSocket] = set()
_ws_lock: asyncio.Lock | None = None  # 在 ASGI loop 建立後才初始化


async def _queue_consumer() -> None:
    while True:
        try:
            event = _event_queue.get_nowait()
            await broadcast(event)
        except _queue.Empty:
            await asyncio.sleep(0.05)
        except Exception:
            pass


app = FastAPI(title="HoneyPot Stats API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
async def _startup():
    global _ws_lock
    _ws_lock = asyncio.Lock()
    asyncio.create_task(_queue_consumer())


def enqueue_event(event: dict) -> None:
    """同步介面：任何 thread 都可以呼叫，不需要 asyncio。"""
    _event_queue.put_nowait(event)


@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    async with _ws_lock:
        _ws_clients.add(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        async with _ws_lock:
            _ws_clients.discard(ws)


async def broadcast(event: dict) -> None:
    payload = json.dumps(event)
    async with _ws_lock:
        clients = list(_ws_clients)
    dead = []
    for ws in clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    if dead:
        async with _ws_lock:
            for ws in dead:
                _ws_clients.discard(ws)
```

其餘 `@app.get(...)` route 定義保持不變。

- [ ] **Step 2: 修改 `honeypot/layer1/logger.py`，移除自建 asyncio loop，改用 `enqueue_event`**

完整替換 logger.py：

```python
import asyncio
import threading
from datetime import datetime
from layer2.db import get_conn, init_db


def _broadcast_sync(event: dict) -> None:
    """把事件放進 stats_api 的 thread-safe queue，在正確的 ASGI loop 廣播。"""
    try:
        from layer3.stats_api import enqueue_event
        enqueue_event(event)
    except Exception:
        pass


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

        _broadcast_sync({
            "type": "command",
            "session_id": session_id,
            "command": command,
            "intent": intent,
            "confidence": confidence,
            "cache_hit": cache_hit,
            "timestamp": datetime.utcnow().isoformat(),
        })

    def http_request(self, session_id: str, method: str, path: str,
                     body: str, response_code: int, harvested_creds: str | None = None) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT INTO http_requests (session_id, method, path, body, response_code, harvested_creds) VALUES (?,?,?,?,?,?)",
            (session_id, method, path, body, response_code, harvested_creds),
        )
        conn.commit()
        conn.close()

        _broadcast_sync({
            "type": "http_request",
            "session_id": session_id,
            "method": method,
            "path": path,
            "timestamp": datetime.utcnow().isoformat(),
        })

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

- [ ] **Step 3: 跑測試**

```bash
cd honeypot && .venv/bin/pytest tests/layer1/test_logger.py tests/layer3/test_stats_api.py -v
```
Expected: 所有測試 PASSED

- [ ] **Step 4: Commit**

```bash
git add honeypot/layer3/stats_api.py honeypot/layer1/logger.py
git commit -m "fix: WebSocket 改用 queue 解決跨 loop 問題，WebSocket client list 改 set+Lock"
```

---

## Task 5：Layer 3 API 修正（B8、B9、B11）

**Files:**
- Modify: `honeypot/layer3/stats_api.py`
- Modify: `honeypot/layer3/report_generator.py`

**B8:** Ollama 失敗回傳的 shell 字串被寫成報告
**B9:** 找不到 session 回 200
**B11:** `/api/config` 暴露 `ollama_host`

- [ ] **Step 1: 修改 `report_generator.py`，加入 Ollama 失敗檢查**

找到：
```python
    report = generate(messages, temperature=0.6, model=get_report_model())

    conn = get_conn()
    conn.execute("UPDATE sessions SET report=? WHERE session_id=?", (report, session_id))
```

改成：

```python
    report = generate(messages, temperature=0.6, model=get_report_model())

    _FAILURE_STRINGS = ("bash: command timed out", "command not found")
    if any(report.strip().startswith(s) for s in _FAILURE_STRINGS):
        return "# Report Generation Failed\nOllama did not respond. Please try again later."

    conn = get_conn()
    conn.execute("UPDATE sessions SET report=? WHERE session_id=?", (report, session_id))
```

- [ ] **Step 2: 修改 `stats_api.py`，讓 get_session 和 get_report 回 404**

找到 `get_session` 函式：

```python
@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    conn = get_conn()
    session = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()
    ...
    if not session:
        return {"error": "not found"}
```

改成：

```python
from fastapi import HTTPException

@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    conn = get_conn()
    session = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()
    commands = conn.execute(
        "SELECT * FROM commands WHERE session_id=? ORDER BY timestamp", (session_id,)
    ).fetchall()
    http_reqs = conn.execute(
        "SELECT * FROM http_requests WHERE session_id=? ORDER BY timestamp", (session_id,)
    ).fetchall()
    conn.close()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        **dict(session),
        "commands": [dict(c) for c in commands],
        "http_requests": [dict(r) for r in http_reqs],
    }
```

- [ ] **Step 3: 修改 `/api/config`，移除 `ollama_host`**

找到 `get_config` 函式，改成：

```python
@app.get("/api/config")
def get_config():
    return {
        "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.1"),
        "ollama_report_model": os.getenv("OLLAMA_REPORT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1")),
        "ssh_port": os.getenv("SSH_PORT", "2222"),
        "http_port": os.getenv("HTTP_PORT", "8080"),
    }
```

- [ ] **Step 4: 修改 `generate_session_report` endpoint，加入 503 錯誤處理**

找到：
```python
@app.post("/api/reports/{session_id}/generate")
def generate_session_report(session_id: str):
    from layer3.report_generator import generate_report
    report = generate_report(session_id)
    return {"report": report}
```

改成：

```python
@app.post("/api/reports/{session_id}/generate")
def generate_session_report(session_id: str):
    from layer3.report_generator import generate_report
    try:
        report = generate_report(session_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Report generation failed") from exc
    if report is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"report": report}
```

- [ ] **Step 5: 跑測試**

```bash
cd honeypot && .venv/bin/pytest tests/layer3/ -v
```
Expected: 所有測試 PASSED

- [ ] **Step 6: Commit**

```bash
git add honeypot/layer3/stats_api.py honeypot/layer3/report_generator.py
git commit -m "fix(layer3): 404 回應、/api/config 移除敏感資訊、Ollama 失敗報告保護"
```

---

## Task 6：前端修正（B12、B13、B14）

**Files:**
- Modify: `honeypot/layer3/frontend/src/components/CommandChart.tsx`
- Modify: `honeypot/layer3/frontend/src/components/IntentChart.tsx`
- Modify: `honeypot/layer3/frontend/src/components/LiveFeed.tsx`

**B12:** CommandChart 沒有 loading/error state
**B13:** IntentChart 用固定寬度，不一致
**B14:** LiveFeed 沒有 reconnect 機制，HTTPS 需要 wss://

- [ ] **Step 1: 完整替換 `CommandChart.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

type CommandStat = { command: string; count: number }

export default function CommandChart() {
  const [data, setData] = useState<CommandStat[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/stats/commands?limit=10')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<CommandStat[]>
      })
      .then(setData)
      .catch(() => setError('Failed to load'))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs mb-3">TOP COMMANDS</div>
      {loading && <div className="text-gray-600 text-sm">Loading...</div>}
      {error && <div className="text-red-500 text-sm">{error}</div>}
      {!loading && !error && data.length === 0 && (
        <div className="text-gray-600 text-sm">No commands yet</div>
      )}
      {!loading && !error && data.length > 0 && (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data} layout="vertical" margin={{ left: 16 }}>
            <XAxis type="number" stroke="#4b5563" tick={{ fontSize: 11 }} />
            <YAxis
              type="category"
              dataKey="command"
              stroke="#4b5563"
              tick={{ fontSize: 10, fill: '#9ca3af' }}
              width={140}
            />
            <Tooltip
              contentStyle={{ background: '#111827', border: '1px solid #374151' }}
              labelStyle={{ color: '#f3f4f6' }}
            />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
```

- [ ] **Step 2: 修改 `IntentChart.tsx`，改用 ResponsiveContainer**

找到 `<PieChart width={280} height={200}>` 那一段，改成：

```tsx
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} dataKey="count" nameKey="intent" cx="50%" cy="50%" outerRadius={70}>
            {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
          </Pie>
          <Tooltip formatter={(v) => [v, 'count']} />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
```

（移除 `PieChart` 上的 `width={280}` 和 `height={200}`，改成外層 `ResponsiveContainer`）

- [ ] **Step 3: 完整替換 `LiveFeed.tsx`，加入 reconnect 和 wss:// 支援**

```tsx
import { useEffect, useRef, useState, useCallback } from 'react'

interface Event { command: string; intent: string; session_id: string; timestamp: string }

const intentColor: Record<string, string> = {
  reconnaissance: 'text-blue-400',
  privilege_escalation: 'text-red-400',
  data_exfiltration: 'text-orange-400',
  persistence: 'text-yellow-400',
  lateral_movement: 'text-purple-400',
  credential_harvesting: 'text-pink-400',
  web_recon: 'text-cyan-400',
  injection_attempt: 'text-rose-500',
  unknown: 'text-gray-400',
}

export default function LiveFeed() {
  const [events, setEvents] = useState<Event[]>([])
  const [connected, setConnected] = useState(false)
  const bottom = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${scheme}://${location.host}/ws/live`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data) as Event
        setEvents(prev => [...prev.slice(-49), ev])
      } catch {}
    }
    ws.onclose = () => {
      setConnected(false)
      // 5 秒後重連
      retryTimer.current = setTimeout(connect, 5000)
    }
    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (retryTimer.current) clearTimeout(retryTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-72 overflow-y-auto font-mono text-sm">
      <div className="flex items-center gap-2 text-xs mb-2">
        <span className={connected ? 'text-green-400' : 'text-yellow-400'}>
          {connected ? '● LIVE' : '○ RECONNECTING...'}
        </span>
      </div>
      {events.length === 0 && <div className="text-gray-600">Waiting for attackers...</div>}
      {events.map((ev, i) => (
        <div key={i} className="flex gap-3 mb-1">
          <span className="text-gray-600 shrink-0">{ev.timestamp?.slice(11, 19)}</span>
          <span className={`shrink-0 w-36 ${intentColor[ev.intent] ?? 'text-gray-400'}`}>{ev.intent}</span>
          <span className="text-green-300 truncate">{ev.command}</span>
        </div>
      ))}
      <div ref={bottom} />
    </div>
  )
}
```

- [ ] **Step 4: Build 驗證**

```bash
cd honeypot/layer3/frontend && npm run build
```
Expected: TypeScript 無錯誤，dist/ 生成

- [ ] **Step 5: Commit**

```bash
git add honeypot/layer3/frontend/src/components/
git commit -m "fix(frontend): CommandChart loading/error state、IntentChart ResponsiveContainer、LiveFeed 重連 + wss"
```

---

## Task 7：小修正（低嚴重性）

**Files:**
- Modify: `honeypot/layer2/db.py`（WAL mode + indexes）
- Modify: `honeypot/layer1/http_server.py`（HTML escape）
- Modify: `honeypot/layer3/stats_api.py`（limit 驗證）

- [ ] **Step 1: 修改 `db.py`，在 `init_db` 加入 WAL mode、busy timeout 和 indexes**

在 `conn.executescript("""...)` 的 `CREATE TABLE` 語句之後加入（在 `""")` 之前）：

```sql
        PRAGMA journal_mode=WAL;
        PRAGMA busy_timeout=5000;
        CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time);
        CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_commands_intent ON commands(intent);
        CREATE INDEX IF NOT EXISTS idx_http_session ON http_requests(session_id, timestamp);
```

- [ ] **Step 2: 修改 `http_server.py` 的 `catch_all`，加入 HTML escape**

在檔案頂部加入 `import html`，然後找到 catch_all 裡的：

```python
        f'<p>The page <code>/{path}</code> could not be found.</p>'
```

改成：

```python
        f'<p>The page <code>/{html.escape(path)}</code> could not be found.</p>'
```

- [ ] **Step 3: 修改 `stats_api.py` 的 `top_commands`，加入 limit 驗證**

找到：
```python
def top_commands(limit: int = 20):
```
改成：
```python
from fastapi import Query

def top_commands(limit: int = Query(default=20, ge=1, le=100)):
```

- [ ] **Step 4: 跑完整測試**

```bash
cd honeypot && .venv/bin/pytest tests/ -v
```
Expected: 所有測試 PASSED

- [ ] **Step 5: Commit**

```bash
git add honeypot/layer2/db.py honeypot/layer1/http_server.py honeypot/layer3/stats_api.py
git commit -m "fix: SQLite WAL mode + indexes、HTML escape、limit 參數驗證"
```

---

## Task 8：更新 README.md 和 CLAUDE.md

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: 更新 `README.md`**

以下區段需要更新（用 Edit 工具逐段修改）：

**SSH 人設說明（第 26 行附近）：**
```
**SSH 人設：** Ubuntu 18.04.6 LTS 電商後台伺服器。只接受常見弱密碼（admin/admin、root/toor、dbadmin/Sup3rS3cr3t!2019 等）登入。常見指令（ls、cat、pwd）直接從規則快取秒回，配備完整的假檔案系統——包含假資料庫憑證的 `/var/www/html/.env`、`/home/admin/backup.sql` MySQL dump，以及設定錯誤的 sudoers 等誘餌檔案。陌生指令才送 LLM 生成回應。
```

**意圖分類器說明（第 30 行附近）：**
```
**意圖分類器：** 關鍵字比對，將 SSH 指令和 HTTP 請求分為 `reconnaissance`、`privilege_escalation`、`data_exfiltration`、`persistence`、`lateral_movement`、`credential_harvesting`（帳密竊取）、`web_recon`（網站偵查）、`injection_attempt`（注入攻擊）。快速路徑處理 80% 以上的情況，不需呼叫 LLM。
```

**Ollama 模型設定（第 60-80 行附近）：**
```bash
ollama pull llama3.1:8b-instruct-q8_0    # 終端回應模型（快速，~8.5GB VRAM）
ollama pull qwen2.5:14b-instruct-q4_K_M  # 報告生成模型（高品質，~9GB VRAM）
```

**.env 範例（第 71-80 行附近）：**
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

**測試 SSH 的指令（第 116-120 行附近）：**
```bash
# SSH（需使用弱密碼，例如 admin/admin 或 root/toor）
ssh -p 2222 admin@localhost          # 密碼: admin
ssh -p 2222 root@localhost           # 密碼: toor
ssh -p 2222 dbadmin@localhost        # 密碼: Sup3rS3cr3t!2019（與 .env 相同）

# 或直接跑自動化 demo 攻擊
./scripts/demo.sh
```

**Dashboard 頁面表格（第 214-218 行附近）：**
```markdown
| 頁面 | 內容 |
|---|---|
| Dashboard | WebSocket 即時攻擊串流、意圖分佈圓餅圖、Top Commands 長條圖、Session 統計 |
| Sessions | 所有 Session 列表，點入可逐條重播每個指令與 LLM 回應 |
| Reports | 每個 Session 的 LLM 生成 Markdown 威脅情報報告（含 MITRE ATT&CK 標籤） |
```

**切換模型區段（第 264-270 行附近）：**
```env
# 終端回應模型（每個 SSH 指令）
OLLAMA_MODEL=llama3.1:8b-instruct-q8_0

# 報告生成模型（session 結束時）
OLLAMA_REPORT_MODEL=qwen2.5:14b-instruct-q4_K_M
```

**檔案結構，補上 shared/：**
```
  shared/
    models.py              # Pydantic 共用資料模型（RespondRequest/RespondResponse）
```

- [ ] **Step 2: 更新 `CLAUDE.md`**

**模型設定說明（第 61 行附近）：**
```
**Two models** — `OLLAMA_MODEL` for terminal responses (low temperature=0.1), `OLLAMA_REPORT_MODEL` for threat reports (temperature=0.6). Both in `.env`. `ollama_client.py` reads both at call time.
```

**HTTP server 說明（第 68 行附近）：**
```
**HTTP server** — each request creates a new `session_id` (IP + uuid4). Intent classifier runs on path+body, result logged to both `http_requests` and `commands` table. Session immediately ends after logging.
```

**WebSocket broadcast 說明（第 70 行附近）：**
```
**WebSocket broadcast** — `logger.py` calls `enqueue_event(event)` (thread-safe sync). `stats_api.py` runs a background task on the ASGI loop that consumes the queue and calls `broadcast()`. Never call `broadcast()` directly from non-async code.
```

**Intent Categories（第 74 行附近）：**
```
`reconnaissance`, `privilege_escalation`, `data_exfiltration`, `persistence`, `lateral_movement`, `credential_harvesting`, `web_recon`, `injection_attempt`, `unknown`
```

**Threat level logic（第 76-79 行附近）：**
```
- Critical: privilege_escalation AND data_exfiltration both seen
- High: privilege_escalation OR data_exfiltration seen
- Medium: persistence or lateral_movement seen
- Low: everything else
```

**補上 shared/ 的 Critical Facts：**
```
**shared/models.py** — single source of truth for `RespondRequest`/`RespondResponse` Pydantic models. `VALID_INTENTS` must be updated whenever `intent_classifier.py` adds new intent categories.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: 更新 README 和 CLAUDE.md 反映 Phase 2 所有改動"
```

---

## 整體執行順序（依賴關係）

| Task | 依賴 | 預估時間 |
|------|------|---------|
| Task 1：VALID_INTENTS | 無 | 5 min |
| Task 2：SSH server | 無 | 20 min |
| Task 3：HTTP server | 無 | 15 min |
| Task 4：WebSocket 架構 | 無 | 20 min |
| Task 5：Layer 3 API | Task 4（stats_api 改過了） | 15 min |
| Task 6：前端 | 無 | 20 min |
| Task 7：小修正 | 無 | 10 min |
| Task 8：文件 | 所有 Task 完成後 | 20 min |
