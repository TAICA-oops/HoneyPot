"""誘餌檔案系統的單一真相來源 (single source of truth)。

SSH 的 `cat`、HTTP 的 `/.env`、以及 LLM system prompt 都從這裡取內容,
確保攻擊者不論從哪個介面、用哪個指令拿到的假資產都完全一致。
要改攻擊者會看到什麼,只改這個檔案。
"""

import re
import time as _time
from datetime import datetime as _datetime, timezone as _timezone

# 蜜罐的「開機時間」：程序啟動往前推約 312 天,讓 uptime 看起來像長期運行的伺服器,
# 且每次查詢都會增加（真實的活伺服器時鐘會走,不會永遠停在同一刻）。
_BOOT_EPOCH = _time.time() - (312 * 86400 + 14 * 3600 + 3 * 60)


def now_utc() -> "_datetime":
    return _datetime.now(_timezone.utc)


def date_str(dt: "_datetime | None" = None) -> str:
    """擬真 `date` 輸出,例如 'Sat Jun  7 14:23:45 UTC 2026'（日為空白補齊兩位）。"""
    dt = dt or now_utc()
    return dt.strftime("%a %b ") + f"{dt.day:2d}" + dt.strftime(" %H:%M:%S UTC %Y")


def uptime_str() -> str:
    """擬真 `uptime` 輸出,uptime 隨真實時間增加。"""
    now = now_utc()
    elapsed = _time.time() - _BOOT_EPOCH
    days = int(elapsed // 86400)
    rem = int(elapsed % 86400)
    hh, mm = rem // 3600, (rem % 3600) // 60
    return (f" {now.strftime('%H:%M:%S')} up {days} days, "
            f"{hh:2d}:{mm:02d},  1 user,  load average: 0.08, 0.03, 0.01")


# ── 憑證 ────────────────────────────────────────────────────────────────────
# 注意:AWS 金鑰刻意避開 AWS 官方文件的範例值 (AKIAIOSFODNN7EXAMPLE / wJalr...)，
# 否則任何攻擊者或掃描器一眼就認出是假的,誘餌價值歸零。以下為格式合法但無效的隨機假值。
DB_PASSWORD = "Sup3rS3cr3t!2019"
AWS_KEY = "AKIA5J7XQZ2NP4RVD3WL"
AWS_SECRET = "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"
MAIL_PASSWORD = "mg_smtp_pass_2019"

# ── /var/www/html/.env ──────────────────────────────────────────────────────
ENV_FILE = f"""\
APP_ENV=production
APP_KEY=base64:3lV7kQmN2pXwR8sT1uYvZaB4cDeF6gHi
DB_HOST=localhost
DB_DATABASE=ecommerce_db
DB_USERNAME=dbadmin
DB_PASSWORD={DB_PASSWORD}
MAIL_HOST=smtp.mailgun.org
MAIL_PASSWORD={MAIL_PASSWORD}
AWS_KEY={AWS_KEY}
AWS_SECRET={AWS_SECRET}
"""

# ── /var/www/html/wp-config.php ─────────────────────────────────────────────
WP_CONFIG = f"""\
<?php
define('DB_NAME','ecommerce_db');
define('DB_USER','dbadmin');
define('DB_PASSWORD','{DB_PASSWORD}');
define('DB_HOST','localhost');
"""

# ── /home/dbadmin/.my.cnf ───────────────────────────────────────────────────
MY_CNF = f"""\
[client]
user=dbadmin
password={DB_PASSWORD}
host=localhost
"""

# ── /home/admin/backup.sql ──────────────────────────────────────────────────
BACKUP_SQL = (
    "-- MySQL dump 10.13  Distrib 5.7.42\n"
    "-- Host: localhost    Database: ecommerce_db\n"
    "CREATE DATABASE ecommerce_db;\nUSE ecommerce_db;\n"
    "INSERT INTO users VALUES (1,'admin','$2y$10$abcdefghijk...');\n"
)

# ── 指令歷史 (history 內建指令 與 ~/.bash_history 共用同一份劇本) ──────────────
# 真實 bash 的 `history` 就是讀 ~/.bash_history + 當前 session,兩者必須一致。
STATIC_HISTORY_COMMANDS = [
    "systemctl status nginx",
    "tail -f /var/log/nginx/access.log",
    f"mysql -u dbadmin -p{DB_PASSWORD} ecommerce_db",
    "df -h",
    "free -m",
    "ls /var/www/html/",
    "nano /var/www/html/.env",
    "systemctl restart nginx",
    "ps aux | grep php",
    "netstat -tulpn",
    "uname -a",
    "uptime",
    "exit",
]
ADMIN_BASH_HISTORY = "\n".join(STATIC_HISTORY_COMMANDS) + "\n"

# ── 系統檔 ──────────────────────────────────────────────────────────────────
ETC_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
backup:x:1002:1002::/home/backup:/bin/sh
dbadmin:x:1003:1003::/home/dbadmin:/bin/bash
ubuntu:x:1004:1004:Ubuntu:/home/ubuntu:/bin/bash
"""

ETC_HOSTS = """\
127.0.0.1\tlocalhost
127.0.1.1\tweb-server-01
10.0.0.5\tdb-internal
10.0.0.10\tbackup-server
"""

PROC_VERSION = (
    "Linux version 4.15.0-213-generic (buildd@lcy02-amd64-013) "
    "(gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) "
    "#224-Ubuntu SMP Mon Jun 19 13:30:52 UTC 2023\n"
)

# 使用者 → UID（與 ETC_PASSWD 保持一致）
UID_MAP = {
    "root": 0, "admin": 1000, "deploy": 1001,
    "backup": 1002, "dbadmin": 1003, "ubuntu": 1004,
}

# 凍結的系統時間（cache 與 LLM prompt 共用,避免時間軸打架）
SYSTEM_DATE = "Mon Jun 19 08:42:17 UTC 2023"

# ── /etc/shadow（雜湊與 ETC_PASSWD 的使用者對應；$6$ SHA-512 格式、無效假值）────
ETC_SHADOW = """\
root:$6$Rj8KpQ2x$9vH3mNpYwQ7nR4tV6yB8mD1sF3hJ5lN0oAcE4gI6uXqR2tV6yB8mD1s:19000:0:99999:7:::
daemon:*:18000:0:99999:7:::
www-data:*:18000:0:99999:7:::
admin:$6$aB4cD2eF$kP9wZ2xQ7nR4tV6yB8mD1sF3hJ5lN0oAcE4gI6uXqR2tV6yB8mD1s:19000:0:99999:7:::
deploy:$6$gH6iJ8kL$mN0oAcE4gI6uXqR2tV6yB8mD1sF3hJ5lN0oAcE4gI6uXqR2tV6yB:19000:0:99999:7:::
backup:$6$mN2oP4qR$sF3hJ5lN0oAcE4gI6uXqR2tV6yB8mD1sF3hJ5lN0oAcE4gI6uXqR2:19000:0:99999:7:::
dbadmin:$6$sT4uV6wX$tV6yB8mD1sF3hJ5lN0oAcE4gI6uXqR2tV6yB8mD1sF3hJ5lN0oAc:19000:0:99999:7:::
ubuntu:$6$yZ6aB8cD$uXqR2tV6yB8mD1sF3hJ5lN0oAcE4gI6uXqR2tV6yB8mD1sF3hJ5lN:19000:0:99999:7:::
"""

# ── /etc/sudoers（admin 的 NOPASSWD 設定錯誤就是誘餌）──────────────────────────
ETC_SUDOERS = """\
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

root    ALL=(ALL:ALL) ALL
%admin  ALL=(ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
admin   ALL=(ALL) NOPASSWD: ALL
"""

# ── /var/log/auth.log ────────────────────────────────────────────────────────
AUTH_LOG = (
    "May 29 08:12:01 web-server-01 sshd[1234]: Failed password for root from 185.220.101.45 port 54321 ssh2\n"
    "May 29 08:12:03 web-server-01 sshd[1235]: Failed password for admin from 185.220.101.45 port 54322 ssh2\n"
    "May 29 08:12:05 web-server-01 sshd[1236]: Accepted password for root from 192.168.1.10 port 22 ssh2\n"
    "May 29 09:33:12 web-server-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n"
    "May 29 10:01:44 web-server-01 sshd[2341]: Failed password for root from 45.33.32.156 port 12345 ssh2\n"
)

# ── 權限模型 ─────────────────────────────────────────────────────────────────
# 私密檔：只有「檔主」與 root 能讀，其餘人 cat 會拿到 Permission denied。
PRIVATE_FILES = {
    "/etc/shadow": "root",
    "/etc/sudoers": "root",
    "/var/log/auth.log": "root",
    "/root/.bash_history": "root",
    "/home/admin/.bash_history": "admin",
    "/home/deploy/.bash_history": "deploy",
    "/home/backup/.bash_history": "backup",
    "/home/dbadmin/.bash_history": "dbadmin",
    "/home/ubuntu/.bash_history": "ubuntu",
    "/home/dbadmin/.my.cnf": "dbadmin",
}


# 擁有 NOPASSWD sudo 的使用者（與 ETC_SUDOERS 的設定一致）；root 永遠有權限。
SUDO_NOPASSWD = {"admin"}


def owner_of(path: str) -> str | None:
    """由路徑推斷擁有者：/root 子樹為 root,/home/<u> 子樹為 <u>,其餘無單一擁有者。"""
    if path == "/root" or path.startswith("/root/"):
        return "root"
    m = re.match(r"^/home/([^/]+)(?:/|$)", path)
    return m.group(1) if m else None


def can_read(path: str, user: str) -> bool:
    if user == "root":
        return True
    # 700 權限的目錄：/root 與任何 .ssh，只有擁有者進得去
    if path == "/root" or path.startswith("/root/"):
        return False
    if "/.ssh/" in path or path.endswith("/.ssh"):
        return owner_of(path) == user
    owner = PRIVATE_FILES.get(path)
    if owner is None:
        return True            # 公開可讀（644 之類）
    return user == owner


def can_write(path: str, user: str) -> bool:
    """攻擊者寫入權限：root 可寫任何處;其餘僅 /tmp、/var/tmp、/dev/shm 與自己家目錄。"""
    if user == "root":
        return True
    if path == "/tmp" or path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
        return True
    owner = owner_of(path)
    if owner is not None:
        return owner == user   # 自己的家目錄子樹
    return False               # /etc、/usr、/var… 系統路徑,非 root 不可寫


# ── 家目錄 ───────────────────────────────────────────────────────────────────
HOME_DIRS = {
    "root": "/root",
    "admin": "/home/admin",
    "deploy": "/home/deploy",
    "backup": "/home/backup",
    "dbadmin": "/home/dbadmin",
    "ubuntu": "/home/ubuntu",
}


def home_for(user: str) -> str:
    return HOME_DIRS.get(user, f"/home/{user}")


# ── 存在的目錄 / 檔案（cd 與 ls 共用，避免「ls 看得到卻 cd 不進去」）──────────────
FAKE_DIRS = {
    "/",
    "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/media", "/mnt",
    "/opt", "/proc", "/root", "/run", "/srv", "/sys", "/tmp", "/usr", "/var",
    "/etc/ssh", "/etc/cron.d",
    "/home/admin", "/home/backup", "/home/dbadmin", "/home/deploy", "/home/ubuntu",
    "/proc/1", "/proc/net",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/local/bin", "/usr/share",
    "/var/backups", "/var/cache", "/var/lib", "/var/log", "/var/mail",
    "/var/opt", "/var/run", "/var/spool", "/var/www", "/var/www/html",
    "/var/www/html/wp-admin", "/var/www/html/wp-content", "/var/www/html/wp-includes",
}

# 已知檔案（cd 進去要回「Not a directory」而不是「No such file」）
FAKE_FILES = {
    "/etc/passwd", "/etc/hosts", "/etc/hostname", "/etc/issue", "/etc/group",
    "/etc/shadow", "/etc/sudoers", "/etc/crontab", "/etc/timezone",
    "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
    "/var/log/auth.log",
    "/var/www/html/.env", "/var/www/html/index.php", "/var/www/html/wp-config.php",
    "/home/admin/.bashrc", "/home/admin/.profile", "/home/admin/.bash_history",
    "/home/admin/backup.sql",
    "/home/dbadmin/.bashrc", "/home/dbadmin/.profile", "/home/dbadmin/.my.cnf",
    "/home/deploy/.bashrc", "/home/deploy/.profile",
    "/home/backup/.bashrc", "/home/backup/.profile",
}


def normalize_path(current_dir: str, target: str) -> str:
    """把使用者輸入的路徑正規化：處理絕對/相對、尾斜線、`.`、`..`、多重斜線。"""
    if not target:
        target = "."
    path = target if target.startswith("/") else current_dir.rstrip("/") + "/" + target
    parts: list[str] = []
    for seg in path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return "/" + "/".join(parts)
