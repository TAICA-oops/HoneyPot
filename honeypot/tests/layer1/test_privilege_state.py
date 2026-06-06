"""提權狀態持續測試 (#4) —— sudo su 之後身分要維持,exit 要逐層退回。"""
import pytest
from layer1.session_manager import SessionManager, detect_escalation


@pytest.fixture
def mgr():
    return SessionManager()


# ── 偵測哪些指令會開啟「持續的」root shell ────────────────────────────────────
def test_detect_sudo_su_variants():
    assert detect_escalation("sudo su") == "root"
    assert detect_escalation("sudo su -") == "root"
    assert detect_escalation("sudo -i") == "root"
    assert detect_escalation("sudo -s") == "root"
    assert detect_escalation("sudo bash") == "root"
    assert detect_escalation("sudo /bin/bash") == "root"


def test_one_shot_sudo_is_not_persistent_escalation():
    # 帶 -c 的單次執行不改變持續 shell 身分
    assert detect_escalation("sudo bash -c 'id'") is None
    assert detect_escalation("sudo cat /etc/shadow") is None
    assert detect_escalation("sudo -l") is None


def test_plain_command_is_not_escalation():
    assert detect_escalation("ls") is None
    assert detect_escalation("whoami") is None


# ── 狀態堆疊 ─────────────────────────────────────────────────────────────────
def test_sudo_su_changes_effective_user_to_root(mgr):
    mgr.create("s", "admin", "1.1.1.1")
    assert mgr.effective_user("s") == "admin"
    mgr.push_user("s", "root", login_shell=True)
    assert mgr.effective_user("s") == "root"
    assert mgr.get("s")["current_dir"] == "/root"   # sudo -i / su - 切到 root 家目錄


def test_exit_from_root_shell_returns_to_login_user(mgr):
    mgr.create("s", "admin", "1.1.1.1")
    mgr.push_user("s", "root", login_shell=True)
    assert mgr.pop_user("s") is True
    assert mgr.effective_user("s") == "admin"
    assert mgr.get("s")["current_dir"] == "/home/admin"   # 退回原本的工作目錄


def test_pop_at_login_level_signals_session_end(mgr):
    mgr.create("s", "admin", "1.1.1.1")
    assert mgr.pop_user("s") is False   # 已在最底層 → 呼叫端應結束 session


def test_escalation_then_read_is_consistent_end_to_end(mgr):
    # 整合：提權前後 cat /etc/shadow 與 whoami 必須前後一致,不會自相矛盾
    from layer2.cache import CacheHandler
    ch = CacheHandler()
    mgr.create("s", "admin", "1.1.1.1")

    before = ch.handle("cat /etc/shadow", mgr.get("s")["current_dir"], mgr.effective_user("s"))
    assert "Permission denied" in before

    mgr.push_user("s", detect_escalation("sudo su -"), login_shell=True)
    after = ch.handle("cat /etc/shadow", mgr.get("s")["current_dir"], mgr.effective_user("s"))
    assert "Permission denied" not in after and "root:" in after
    assert ch.handle("whoami", mgr.get("s")["current_dir"], mgr.effective_user("s")) == "root\n"

    mgr.pop_user("s")
    assert ch.handle("whoami", mgr.get("s")["current_dir"], mgr.effective_user("s")) == "admin\n"
