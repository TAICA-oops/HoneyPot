import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
from layer2.db import get_conn

load_dotenv()

app = FastAPI(title="HoneyPot Stats API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_ws_clients: list[WebSocket] = []

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
        return {"error": "not found"}
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
def top_commands(limit: int = 20):
    conn = get_conn()
    rows = conn.execute(
        "SELECT command, COUNT(*) as count FROM commands GROUP BY command ORDER BY count DESC LIMIT ?",
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
    return {"report": row[0] if row else None}

@app.post("/api/reports/{session_id}/generate")
def generate_session_report(session_id: str):
    from layer3.report_generator import generate_report
    report = generate_report(session_id)
    return {"report": report}

@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_clients.remove(ws)

async def broadcast(event: dict) -> None:
    import json
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_text(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)

def run() -> None:
    port = int(os.getenv("STATS_API_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    run()
