import pytest
from layer1.session_manager import SessionManager

@pytest.fixture
def mgr():
    return SessionManager()

def test_create_session(mgr):
    s = mgr.create("sess1", "root", "1.2.3.4")
    assert s["current_dir"] == "/home/admin"
    assert s["user"] == "root"
    assert s["history"] == []

def test_cd_to_valid_dir(mgr):
    mgr.create("s1", "root", "1.1.1.1")
    new_dir, err = mgr.handle_cd("s1", "cd /etc")
    assert new_dir == "/etc"
    assert err == ""
    assert mgr.get("s1")["current_dir"] == "/etc"

def test_cd_to_invalid_dir(mgr):
    mgr.create("s1", "root", "1.1.1.1")
    _, err = mgr.handle_cd("s1", "cd /nonexistent")
    assert "No such file or directory" in err
    assert mgr.get("s1")["current_dir"] == "/home/admin"

def test_cd_dotdot(mgr):
    mgr.create("s1", "root", "1.1.1.1")
    mgr.handle_cd("s1", "cd /var/www/html")
    new_dir, err = mgr.handle_cd("s1", "cd ..")
    assert new_dir == "/var/www"
    assert err == ""

def test_history_capped_at_10(mgr):
    mgr.create("s1", "root", "1.1.1.1")
    for i in range(12):
        mgr.push_history("s1", f"cmd{i}")
    assert len(mgr.get("s1")["history"]) == 10
    assert mgr.get("s1")["history"][-1] == "cmd11"
