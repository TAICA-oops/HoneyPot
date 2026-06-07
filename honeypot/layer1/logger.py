from datetime import datetime
from layer2.db import get_conn, init_db


_THREAT_ORDER = {None: 0, "": 0, "Unknown": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _threat_rank(level: str | None) -> int:
    return _THREAT_ORDER.get(level, 0)


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
        conn.execute(
            "UPDATE sessions SET total_cmds=(SELECT COUNT(*) FROM commands WHERE session_id=?) WHERE session_id=?",
            (session_id, session_id),
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

    def recent_pairs_for_ip(self, ip: str, limit: int = 15,
                            exclude_session: str | None = None) -> list[tuple[str, str]]:
        """取得某來源 IP 先前 SSH session 的指令+回應(時間序),供重連時重建脈絡。"""
        conn = get_conn(self.db_path)
        rows = conn.execute(
            """SELECT c.command, c.response
               FROM commands c JOIN sessions s ON c.session_id = s.session_id
               WHERE s.attacker_ip = ? AND s.protocol = 'ssh'
                 AND (? IS NULL OR c.session_id != ?)
               ORDER BY c.timestamp DESC, c.id DESC LIMIT ?""",
            (ip, exclude_session, exclude_session, limit),
        ).fetchall()
        conn.close()
        return [(r[0], r[1] or "") for r in reversed(rows)]   # 取最近 N 筆,再轉回時間序

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

    def session_touch(self, session_id: str, threat_level: str) -> None:
        """更新 end_time/total_cmds,並把 threat_level 提升為現有與新值中較高者。

        用於 HTTP 同 IP 聚合：後續低風險請求不可把整段 session 的等級壓回去。
        """
        conn = get_conn(self.db_path)
        row = conn.execute(
            "SELECT threat_level FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        current = row[0] if row else None
        higher = current if _threat_rank(current) >= _threat_rank(threat_level) else threat_level
        conn.execute(
            """UPDATE sessions SET
               end_time=CURRENT_TIMESTAMP,
               total_cmds=(SELECT COUNT(*) FROM commands WHERE session_id=?),
               threat_level=?
               WHERE session_id=?""",
            (session_id, higher, session_id),
        )
        conn.commit()
        conn.close()
