import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

@pytest.fixture
def client():
    from layer2.main import app
    return TestClient(app)

def test_respond_cache_hit(client):
    payload = {
        "session_id": "test-1",
        "protocol": "ssh",
        "command": "whoami",
        "current_dir": "/home/admin",
        "user": "admin",
        "history": [],
    }
    resp = client.post("/respond", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "test-1"
    assert data["cache_hit"] is True
    assert "admin" in data["response"]
    assert data["intent"] in ("reconnaissance", "unknown")

def test_respond_returns_required_fields(client):
    payload = {
        "session_id": "test-2",
        "protocol": "ssh",
        "command": "pwd",
        "current_dir": "/etc",
        "user": "root",
        "history": [],
    }
    resp = client.post("/respond", json=payload)
    data = resp.json()
    for key in ("session_id", "response", "intent", "confidence", "cache_hit"):
        assert key in data

def test_respond_http_protocol(client):
    payload = {
        "session_id": "test-3",
        "protocol": "http",
        "command": "GET /wp-admin",
        "current_dir": "/",
        "user": "anonymous",
        "history": [],
    }
    resp = client.post("/respond", json=payload)
    assert resp.status_code == 200

def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}
