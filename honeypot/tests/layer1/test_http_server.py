"""HTTP 蜜罐測試：同 IP 聚合、phpMyAdmin SQL 收割、威脅等級取最高。"""
import sqlite3
import pytest
from fastapi.testclient import TestClient
from layer2.db import init_db


@pytest.fixture
def client(tmp_db):
    init_db(tmp_db)
    from layer1.http_server import app
    return TestClient(app)


def test_same_ip_requests_aggregate_into_one_session(client, tmp_db):
    client.get("/wp-admin/")
    client.get("/.env")
    client.get("/phpmyadmin/")
    conn = sqlite3.connect(tmp_db)
    n_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    n_reqs = conn.execute("SELECT COUNT(*) FROM http_requests").fetchone()[0]
    conn.close()
    assert n_sessions == 1   # 不再每個請求一個 session 洗版 dashboard
    assert n_reqs == 3


def test_phpmyadmin_post_captures_sql_query(client, tmp_db):
    client.post("/phpmyadmin", data={
        "pma_username": "root", "pma_password": "", "server": "1",
        "sql_query": "SELECT version()",
    })
    conn = sqlite3.connect(tmp_db)
    body, creds = conn.execute(
        "SELECT body, harvested_creds FROM http_requests ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    assert "SELECT version()" in body
    assert "root" in creds


def test_session_threat_keeps_highest_not_last(client, tmp_db):
    client.get("/about")                                              # Low
    client.post("/wp-login.php", data={"log": "admin", "pwd": "x"})   # credential_harvesting → High
    client.get("/contact")                                           # Low，不可把等級壓回去
    conn = sqlite3.connect(tmp_db)
    threat = conn.execute("SELECT threat_level FROM sessions").fetchone()[0]
    conn.close()
    assert threat == "High"
