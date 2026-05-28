import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

def get_db_path() -> str:
    return os.getenv("DB_PATH", "./honeypot.db")

def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or get_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str | None = None) -> None:
    conn = get_conn(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            protocol     TEXT,
            attacker_ip  TEXT,
            start_time   DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time     DATETIME,
            total_cmds   INTEGER DEFAULT 0,
            threat_level TEXT,
            report       TEXT
        );
        CREATE TABLE IF NOT EXISTS commands (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT,
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
            command      TEXT,
            response     TEXT,
            intent       TEXT,
            confidence   REAL,
            cache_hit    BOOLEAN
        );
        CREATE TABLE IF NOT EXISTS http_requests (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id       TEXT,
            timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
            method           TEXT,
            path             TEXT,
            body             TEXT,
            response_code    INTEGER,
            harvested_creds  TEXT
        );
        PRAGMA journal_mode=WAL;
        PRAGMA busy_timeout=5000;
        CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_time);
        CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_commands_intent ON commands(intent);
        CREATE INDEX IF NOT EXISTS idx_http_session ON http_requests(session_id, timestamp);
    """)
    conn.commit()
    conn.close()
