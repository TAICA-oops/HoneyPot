"""誘餌檔的 head/tail/wc 與 cat 必須一致（攻擊者用不同工具讀同一檔不該對不上）。"""
from layer2.cache import CacheHandler

ENV = "/var/www/html/.env"


def _cat(ch, path, user="admin"):
    return ch.handle(f"cat {path}", "/", user)


def test_head_returns_first_lines_of_canonical_content():
    ch = CacheHandler()
    full = _cat(ch, ENV).splitlines()
    out = ch.handle(f"head -n 3 {ENV}", "/", "admin")
    assert out == "\n".join(full[:3]) + "\n"


def test_head_default_is_ten_lines():
    ch = CacheHandler()
    out = ch.handle(f"head {ENV}", "/", "admin")
    assert out == _cat(ch, ENV)   # .env 只有 10 行,head 預設 10 行 → 全部


def test_tail_returns_last_lines():
    ch = CacheHandler()
    full = _cat(ch, "/home/admin/backup.sql").splitlines()
    out = ch.handle("tail -n 2 /home/admin/backup.sql", "/", "admin")
    assert out == "\n".join(full[-2:]) + "\n"


def test_wc_c_matches_cat_byte_count():
    ch = CacheHandler()
    n = len(_cat(ch, ENV))
    out = ch.handle(f"wc -c {ENV}", "/", "admin")
    assert out.split()[0] == str(n)
    assert ENV in out


def test_wc_l_matches_line_count():
    ch = CacheHandler()
    n = len(_cat(ch, ENV).splitlines())
    out = ch.handle(f"wc -l {ENV}", "/", "admin")
    assert out.split()[0] == str(n)


def test_head_respects_permissions():
    ch = CacheHandler()
    # dbadmin 不能 head admin 的 600 .bash_history
    out = ch.handle("head /home/admin/.bash_history", "/", "dbadmin")
    assert "Permission denied" in out


def test_head_unknown_file_delegates_to_llm():
    assert CacheHandler().handle("head /var/log/syslog", "/", "admin") is None


# ── grep 對誘餌檔確定性（攻擊者 grep 撈密碼）────────────────────────────────
def test_grep_matches_only_matching_lines():
    out = CacheHandler().handle("grep DB_PASSWORD /var/www/html/.env", "/", "admin")
    assert "DB_PASSWORD=" in out
    assert "APP_ENV" not in out


def test_grep_n_adds_line_numbers():
    out = CacheHandler().handle("grep -n root /etc/passwd", "/", "admin")
    assert out.startswith("1:")


def test_grep_i_case_insensitive():
    out = CacheHandler().handle("grep -i db_password /var/www/html/.env", "/", "admin")
    assert "DB_PASSWORD" in out


def test_grep_unknown_file_delegates_to_llm():
    assert CacheHandler().handle("grep x /var/log/syslog", "/", "admin") is None


def test_grep_respects_permission():
    out = CacheHandler().handle("grep root /etc/shadow", "/", "admin")
    assert "Permission denied" in out
