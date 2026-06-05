import os
import asyncio
import json
import queue as _queue
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import uvicorn
import httpx
from layer2.db import get_conn

_geo_cache: dict[str, dict] = {}

load_dotenv()

# Thread-safe event queue：logger 往這裡放事件（同步），ASGI loop 消費
_event_queue: _queue.SimpleQueue = _queue.SimpleQueue()

# WebSocket clients：set + asyncio.Lock 避免 race condition
_ws_clients: set[WebSocket] = set()
_ws_lock: asyncio.Lock | None = None


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


@app.get("/api/sessions")
def list_sessions():
    conn = get_conn()
    rows = conn.execute(
        "SELECT session_id, protocol, attacker_ip, start_time, end_time, total_cmds, threat_level "
        "FROM sessions ORDER BY start_time DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


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


@app.get("/api/stats/intents")
def intent_stats():
    conn = get_conn()
    rows = conn.execute(
        "SELECT intent, COUNT(*) as count FROM commands GROUP BY intent ORDER BY count DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/stats/commands")
def top_commands(limit: int = Query(default=20, ge=1, le=100)):
    conn = get_conn()
    rows = conn.execute(
        "SELECT command, COUNT(*) as count FROM commands GROUP BY command ORDER BY count DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/stats/recent")
def recent_commands(limit: int = Query(default=50, ge=1, le=200)):
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, session_id, command, intent, timestamp FROM commands ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/stats/timeline")
def timeline():
    conn = get_conn()
    rows = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, COUNT(*) as count "
        "FROM commands GROUP BY hour ORDER BY hour"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/reports/{session_id}")
def get_report(session_id: str):
    conn = get_conn()
    row = conn.execute("SELECT report FROM sessions WHERE session_id=?", (session_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"report": row[0]}


@app.post("/api/reports/{session_id}/generate")
def generate_session_report(session_id: str, lang: str = Query(default="en", pattern="^(en|zh)$")):
    from layer3.report_generator import generate_report
    try:
        report = generate_report(session_id, lang=lang)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Report generation failed") from exc
    if report is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"report": report}


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


@app.get("/api/stats/geo")
def geo_stats():
    conn = get_conn()
    rows = conn.execute(
        "SELECT attacker_ip, COUNT(*) as sessions FROM sessions GROUP BY attacker_ip ORDER BY sessions DESC"
    ).fetchall()
    conn.close()

    ip_rows = [dict(r) for r in rows]
    results = []

    external = [r for r in ip_rows if not r["attacker_ip"].startswith("127.") and r["attacker_ip"] not in ("::1", "localhost")]
    local    = [r for r in ip_rows if r not in external]

    if external:
        try:
            batch = [{"query": r["attacker_ip"]} for r in external]
            uncached = [b for b in batch if b["query"] not in _geo_cache]
            if uncached:
                resp = httpx.post("http://ip-api.com/batch", json=uncached, timeout=5)
                for item in resp.json():
                    _geo_cache[item.get("query", "")] = item
            for r in external:
                geo = _geo_cache.get(r["attacker_ip"], {})
                results.append({
                    "ip": r["attacker_ip"],
                    "country": geo.get("country", "Unknown"),
                    "country_code": geo.get("countryCode", "??"),
                    "city": geo.get("city", ""),
                    "lat": geo.get("lat", 0),
                    "lon": geo.get("lon", 0),
                    "sessions": r["sessions"],
                })
        except Exception:
            for r in external:
                results.append({"ip": r["attacker_ip"], "country": "Unknown", "country_code": "??",
                                 "city": "", "lat": 0, "lon": 0, "sessions": r["sessions"]})

    for r in local:
        results.append({"ip": r["attacker_ip"], "country": "Local / Simulation",
                         "country_code": "LO", "city": "localhost",
                         "lat": 25.0, "lon": 121.5, "sessions": r["sessions"]})
    return results


@app.get("/api/config")
def get_config():
    return {
        "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.1"),
        "ollama_report_model": os.getenv("OLLAMA_REPORT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1")),
        "ssh_port": os.getenv("SSH_PORT", "2222"),
        "http_port": os.getenv("HTTP_PORT", "8080"),
    }


def run() -> None:
    port = int(os.getenv("STATS_API_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    run()
