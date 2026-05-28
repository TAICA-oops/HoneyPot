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
