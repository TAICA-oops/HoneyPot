"""假終端真實性測試 —— 攻擊者交叉比對指令時不該發現破綻。"""
import re
from layer2.cache import CacheHandler


# ── 權限模型 (#2 root 能讀 shadow / #3 非檔主不能讀他人私密檔) ─────────────────
def test_root_can_read_shadow():
    out = CacheHandler().handle("cat /etc/shadow", "/", "root")
    assert "Permission denied" not in out
    assert "root:" in out


def test_admin_cannot_read_shadow():
    out = CacheHandler().handle("cat /etc/shadow", "/", "admin")
    assert "Permission denied" in out


def test_non_owner_cannot_read_other_users_private_history():
    # dbadmin 不該讀得到 admin 的 600 權限 .bash_history
    out = CacheHandler().handle("cat /home/admin/.bash_history", "/", "dbadmin")
    assert "Permission denied" in out


def test_owner_can_read_own_private_history():
    out = CacheHandler().handle("cat /home/admin/.bash_history", "/home/admin", "admin")
    assert "Permission denied" not in out
    assert out.strip() != ""


def test_root_can_read_any_private_file():
    out = CacheHandler().handle("cat /home/admin/.bash_history", "/", "root")
    assert "Permission denied" not in out


# ── history 與 ~/.bash_history 一致 (#10) ────────────────────────────────────
def test_history_and_bash_history_share_same_script():
    ch = CacheHandler()
    hist = ch.handle("history", "/home/admin", "admin")
    bash_hist = ch.handle("cat /home/admin/.bash_history", "/home/admin", "admin")
    for line in bash_hist.strip().splitlines():
        assert line in hist, f"{line!r} 出現在 .bash_history 卻不在 history"


# ── ls -l 宣稱大小 == 實際 cat 內容長度 (#8) ─────────────────────────────────
def _size_of_entry(long_listing: str, name: str) -> int:
    line = [l for l in long_listing.splitlines() if l.endswith(" " + name)][0]
    return int(line.split()[4])


def test_ls_long_size_matches_env_content():
    ch = CacheHandler()
    longout = ch.handle("ls -l /var/www/html", "/", "admin")
    assert _size_of_entry(longout, ".env") == len(ch.handle("cat /var/www/html/.env", "/", "admin"))


def test_ls_long_size_matches_wp_config_content():
    ch = CacheHandler()
    longout = ch.handle("ls -l /var/www/html", "/", "admin")
    assert _size_of_entry(longout, "wp-config.php") == len(
        ch.handle("cat /var/www/html/wp-config.php", "/", "admin"))


def test_ls_long_size_matches_backup_sql_content():
    ch = CacheHandler()
    longout = ch.handle("ls -l /home/admin", "/", "admin")
    assert _size_of_entry(longout, "backup.sql") == len(
        ch.handle("cat /home/admin/backup.sql", "/", "admin"))


# ── ls 路徑正規化 (#11 尾斜線 / . / 相對路徑) ────────────────────────────────
def test_ls_trailing_slash_equivalent():
    ch = CacheHandler()
    assert ch.handle("ls /home/admin/", "/", "admin") == ch.handle("ls /home/admin", "/", "admin")


def test_ls_dot_equals_current_dir():
    ch = CacheHandler()
    assert ch.handle("ls .", "/home/admin", "admin") == ch.handle("ls /home/admin", "/", "admin")


def test_ls_known_dir_without_listing_delegates_to_llm():
    # /var/log 在 `ls /var` 中出現,所以它存在;沒有明確清單時交給 LLM (回 None)
    assert CacheHandler().handle("ls /var/log", "/", "admin") is None


# ── ubuntu 帳號全棧一致 (#ubuntu 可登入卻不存在於系統觀) ──────────────────────
def test_ubuntu_account_consistent_across_views():
    ch = CacheHandler()
    # 可登入的 ubuntu 必須出現在 passwd、/home 列表,且 id 不能和 admin 撞 uid
    assert "ubuntu" in ch.handle("cat /etc/passwd", "/", "admin")
    assert "ubuntu" in ch.handle("ls /home", "/", "admin")
    assert "1004" in ch.handle("id", "/home/ubuntu", "ubuntu")


# ── 一次性 sudo 以 root 執行 (與提權後 cat 一致) ────────────────────────────────
def test_sudo_read_runs_as_root():
    out = CacheHandler().handle("sudo cat /etc/shadow", "/home/admin", "admin")
    assert out is not None
    assert "Permission denied" not in out
    assert "root:" in out


def test_sudo_whoami_returns_root():
    assert CacheHandler().handle("sudo whoami", "/home/admin", "admin") == "root\n"


def test_sudo_l_shows_nopasswd_for_admin():
    out = CacheHandler().handle("sudo -l", "/home/admin", "admin")
    assert "NOPASSWD" in out


def test_sudo_l_denies_unprivileged_user():
    out = CacheHandler().handle("sudo -l", "/home/backup", "backup")
    assert "may not run sudo" in out


# ── ss/netstat 顯示攻擊者自己的連線 (#18) ────────────────────────────────────
def test_ss_shows_attacker_connection():
    out = CacheHandler().handle("ss -tnp", "/home/admin", "admin", attacker_ip="203.0.113.9")
    assert "203.0.113.9" in out
    assert "10.0.0.1:54321" not in out   # 不再顯示與攻擊者無關的寫死連線


def test_netstat_shows_attacker_connection():
    out = CacheHandler().handle("netstat -an", "/home/admin", "admin", attacker_ip="203.0.113.9")
    assert "203.0.113.9" in out


# ── id 顯示 sudo 群組,與 sudoers 設定一致 ────────────────────────────────────
def test_id_admin_is_in_sudo_group():
    out = CacheHandler().handle("id", "/home/admin", "admin")
    assert "27(sudo)" in out


def test_id_unprivileged_user_not_in_sudo_group():
    out = CacheHandler().handle("id", "/home/backup", "backup")
    assert "sudo" not in out
