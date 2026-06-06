import pytest
from layer1.session_manager import SessionManager

@pytest.fixture
def mgr():
    return SessionManager()

def test_create_session_starts_in_user_home(mgr):
    # 登入後應落在「該使用者的家目錄」,而非永遠 /home/admin
    s = mgr.create("sess1", "root", "1.2.3.4")
    assert s["current_dir"] == "/root"
    assert s["user"] == "root"
    assert s["history"] == []


def test_create_session_dbadmin_home(mgr):
    s = mgr.create("s_db", "dbadmin", "1.2.3.4")
    assert s["current_dir"] == "/home/dbadmin"


def test_cd_into_dir_shown_by_ls(mgr):
    # `ls /var` 會列出 log,所以 `cd /var/log` 必須成功（不能 ls 得到卻 cd 不進去）
    mgr.create("s1", "admin", "1.1.1.1")
    new_dir, err = mgr.handle_cd("s1", "cd /var/log")
    assert err == ""
    assert new_dir == "/var/log"


def test_cd_into_top_level_fhs_dir(mgr):
    mgr.create("s1", "admin", "1.1.1.1")
    new_dir, err = mgr.handle_cd("s1", "cd /bin")
    assert err == ""
    assert new_dir == "/bin"


def test_cd_into_wp_subdir(mgr):
    mgr.create("s1", "admin", "1.1.1.1")
    new_dir, err = mgr.handle_cd("s1", "cd /var/www/html/wp-admin")
    assert err == ""
    assert new_dir == "/var/www/html/wp-admin"


def test_cd_into_file_reports_not_a_directory(mgr):
    mgr.create("s1", "admin", "1.1.1.1")
    _, err = mgr.handle_cd("s1", "cd /var/www/html/.env")
    assert "Not a directory" in err

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
    assert mgr.get("s1")["current_dir"] == "/root"   # root 家目錄，cd 失敗後不變

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
