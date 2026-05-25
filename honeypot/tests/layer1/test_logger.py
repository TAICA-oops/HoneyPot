import sqlite3
import pytest
from layer2.db import init_db
from layer1.logger import Logger

def test_log_session_start(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("sess1", "ssh", "1.2.3.4")
    conn = sqlite3.connect(tmp_db)
    row = conn.execute("SELECT * FROM sessions WHERE session_id='sess1'").fetchone()
    conn.close()
    assert row is not None
    assert row[1] == "ssh"
    assert row[2] == "1.2.3.4"

def test_log_command(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("sess1", "ssh", "1.2.3.4")
    log.command("sess1", "whoami", "admin", "reconnaissance", 0.95, True)
    conn = sqlite3.connect(tmp_db)
    row = conn.execute("SELECT * FROM commands WHERE session_id='sess1'").fetchone()
    conn.close()
    assert row[3] == "whoami"
    assert row[5] == "reconnaissance"
    assert row[7] == 1  # cache_hit True

def test_log_session_end(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("sess1", "ssh", "1.2.3.4")
    log.command("sess1", "ls", "bin boot etc", "reconnaissance", 0.9, True)
    log.session_end("sess1", "Medium")
    conn = sqlite3.connect(tmp_db)
    row = conn.execute("SELECT * FROM sessions WHERE session_id='sess1'").fetchone()
    conn.close()
    assert row[4] is not None   # end_time set
    assert row[5] == 1          # total_cmds
    assert row[6] == "Medium"   # threat_level
