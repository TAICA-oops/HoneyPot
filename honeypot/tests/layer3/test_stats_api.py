import sqlite3
import pytest
from fastapi.testclient import TestClient
from layer2.db import init_db

@pytest.fixture
def client(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    conn.execute("INSERT INTO sessions VALUES ('s1','ssh','1.2.3.4',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,3,'High',NULL)")
    conn.execute("INSERT INTO commands VALUES (1,'s1',CURRENT_TIMESTAMP,'whoami','admin','reconnaissance',0.95,1)")
    conn.execute("INSERT INTO commands VALUES (2,'s1',CURRENT_TIMESTAMP,'sudo su','','privilege_escalation',0.95,0)")
    conn.commit()
    conn.close()
    from layer3.stats_api import app
    return TestClient(app)

def test_get_sessions(client):
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["session_id"] == "s1"

def test_get_session_detail(client):
    resp = client.get("/api/sessions/s1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "s1"
    assert len(data["commands"]) == 2

def test_intent_stats(client):
    resp = client.get("/api/stats/intents")
    assert resp.status_code == 200
    data = resp.json()
    intents = {d["intent"] for d in data}
    assert "reconnaissance" in intents

def test_top_commands(client):
    resp = client.get("/api/stats/commands")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
