import sqlite3
import os
import pytest
from layer2.db import init_db

def test_init_db_creates_tables(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "sessions" in tables
    assert "commands" in tables
    assert "http_requests" in tables
