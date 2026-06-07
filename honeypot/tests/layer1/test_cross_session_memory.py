"""跨連線記憶 (#cross-connection memory)：SSH 重連時用該 IP 既有 SQLite 紀錄
重建對話脈絡餵回 LLM,讓蜜罐「記得」攻擊者。"""
import pytest
from layer2.db import init_db
from layer1.logger import Logger
from layer1.session_manager import SessionManager


def test_recent_pairs_for_ip_returns_chronological(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("s1", "ssh", "9.9.9.9")
    log.command("s1", "whoami", "admin\n", "reconnaissance", 0.9, True)
    log.command("s1", "ls", "bin\n", "reconnaissance", 0.9, True)
    log.session_start("s2", "ssh", "9.9.9.9")          # 同 IP 重連
    pairs = log.recent_pairs_for_ip("9.9.9.9", limit=10, exclude_session="s2")
    assert [c for c, r in pairs] == ["whoami", "ls"]


def test_recent_pairs_excludes_other_ips(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("a", "ssh", "1.1.1.1")
    log.command("a", "secret", "x", "unknown", 0.1, False)
    log.session_start("b", "ssh", "2.2.2.2")
    assert log.recent_pairs_for_ip("2.2.2.2", limit=10) == []


def test_recent_pairs_excludes_http_sessions(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("h", "http", "3.3.3.3")
    log.command("h", "HTTP GET /x", "", "web_recon", 0.9, True)
    assert log.recent_pairs_for_ip("3.3.3.3", limit=10) == []


def test_seed_history_populates_session(tmp_db):
    mgr = SessionManager()
    mgr.create("s", "admin", "1.2.3.4")
    mgr.seed_history("s", [("whoami", "admin\n"), ("cat /etc/passwd", "root:x:0:0\n")])
    sess = mgr.get("s")
    assert ("whoami", "admin\n") in sess["history_pairs"]
    assert "whoami" in sess["history"]   # 向後相容的舊歷史也要有
