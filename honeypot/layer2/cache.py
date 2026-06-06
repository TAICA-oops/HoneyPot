import re
from shared import fake_fs

_ETC_PASSWD = fake_fs.ETC_PASSWD
_ETC_HOSTS = fake_fs.ETC_HOSTS
_BAIT_ENV = fake_fs.ENV_FILE
_PROC_VERSION = fake_fs.PROC_VERSION
_UID_MAP = fake_fs.UID_MAP

_LS_MAP = {
    "/":              "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var\n",
    "/etc":           "cron.d  crontab  group  hosts  hostname  issue  passwd  shadow  ssh  sudoers  timezone\n",
    "/home":          "admin  backup  dbadmin  deploy  ubuntu\n",
    "/home/admin":    ".bash_history  .bashrc  .profile  backup.sql\n",
    "/home/backup":   ".bashrc  .profile\n",
    "/home/dbadmin":  ".bashrc  .my.cnf  .profile\n",
    "/home/deploy":   ".bashrc  .profile\n",
    "/home/ubuntu":   ".bashrc  .profile\n",
    "/var/www/html":  ".env  index.php  wp-config.php  wp-admin  wp-content  wp-includes\n",
    "/tmp":           "\n",
    "/var/www":       "html\n",
    "/var":           "backups  cache  lib  log  mail  opt  run  spool  www\n",
    "/proc":          "1  cpuinfo  meminfo  net  version\n",
    "/opt":           "\n",
    "/usr/bin":       "awk  bash  cat  curl  find  grep  ls  python3  ssh  tar  wget\n",
}

# 與實際 cat 內容長度一致的誘餌檔大小（避免 `ls -l` 宣稱值和 `cat`/`wc -c` 對不上）
_SZ_ENV = len(fake_fs.ENV_FILE)
_SZ_WPCONFIG = len(fake_fs.WP_CONFIG)
_SZ_BACKUP = len(fake_fs.BACKUP_SQL)
_SZ_BASH_HIST = len(fake_fs.ADMIN_BASH_HISTORY)
_SZ_MYCNF = len(fake_fs.MY_CNF)

_LS_LONG_MAP = {
    "/home/admin": (
        "total 44\n"
        "drwxr-xr-x 3 admin admin 4096 Jun 19 08:42 .\n"
        "drwxr-xr-x 6 root  root  4096 Jun 19  2021 ..\n"
        f"-rw------- 1 admin admin {_SZ_BASH_HIST:>4} Jun 19 08:42 .bash_history\n"
        "-rw-r--r-- 1 admin admin 3526 Jun 19  2021 .bashrc\n"
        "-rw-r--r-- 1 admin admin  807 Jun 19  2021 .profile\n"
        f"-rw-r--r-- 1 admin admin {_SZ_BACKUP:>4} Jun 19  2022 backup.sql\n"
    ),
    "/home/dbadmin": (
        "total 28\n"
        "drwxr-xr-x 2 dbadmin dbadmin 4096 Jun 19  2021 .\n"
        "drwxr-xr-x 6 root    root    4096 Jun 19  2021 ..\n"
        "-rw-r--r-- 1 dbadmin dbadmin 3526 Jun 19  2021 .bashrc\n"
        f"-rw------- 1 dbadmin dbadmin {_SZ_MYCNF:>4} Jun 19  2021 .my.cnf\n"
        "-rw-r--r-- 1 dbadmin dbadmin  807 Jun 19  2021 .profile\n"
    ),
    "/home/backup": (
        "total 20\n"
        "drwxr-xr-x 2 backup backup 4096 Jun 19  2021 .\n"
        "drwxr-xr-x 6 root   root   4096 Jun 19  2021 ..\n"
        "-rw-r--r-- 1 backup backup 3526 Jun 19  2021 .bashrc\n"
        "-rw-r--r-- 1 backup backup  807 Jun 19  2021 .profile\n"
    ),
    "/home/deploy": (
        "total 20\n"
        "drwxr-xr-x 2 deploy deploy 4096 Jun 19  2021 .\n"
        "drwxr-xr-x 6 root   root   4096 Jun 19  2021 ..\n"
        "-rw-r--r-- 1 deploy deploy 3526 Jun 19  2021 .bashrc\n"
        "-rw-r--r-- 1 deploy deploy  807 Jun 19  2021 .profile\n"
    ),
    "/home": (
        "total 28\n"
        "drwxr-xr-x  7 root    root    4096 Jun 19  2021 .\n"
        "drwxr-xr-x 18 root    root    4096 Jun 19  2021 ..\n"
        "drwxr-xr-x  3 admin   admin   4096 Jun 19 08:42 admin\n"
        "drwxr-xr-x  2 backup  backup  4096 Jun 19  2021 backup\n"
        "drwxr-xr-x  2 dbadmin dbadmin 4096 Jun 19  2021 dbadmin\n"
        "drwxr-xr-x  2 deploy  deploy  4096 Jun 19  2021 deploy\n"
        "drwxr-xr-x  2 ubuntu  ubuntu  4096 Jun 19  2021 ubuntu\n"
    ),
    "/var/www/html": (
        "total 56\n"
        "drwxr-xr-x 4 www-data www-data 4096 Jun 19  2021 .\n"
        "drwxr-xr-x 3 www-data www-data 4096 Jun 19  2021 ..\n"
        f"-rw-r--r-- 1 www-data www-data {_SZ_ENV:>4} Jun 19  2021 .env\n"
        "-rw-r--r-- 1 www-data www-data 3284 Jun 19  2021 index.php\n"
        f"-rw-r--r-- 1 www-data www-data {_SZ_WPCONFIG:>4} Jun 19  2021 wp-config.php\n"
        "drwxr-xr-x 2 www-data www-data 4096 Jun 19  2021 wp-admin\n"
        "drwxr-xr-x 5 www-data www-data 4096 Jun 19  2021 wp-content\n"
        "drwxr-xr-x 8 www-data www-data 4096 Jun 19  2021 wp-includes\n"
    ),
    "/etc": (
        "total 80\n"
        "drwxr-xr-x 12 root root   4096 Jun 19  2021 .\n"
        "drwxr-xr-x 18 root root   4096 Jun 19  2021 ..\n"
        "drwxr-xr-x  2 root root   4096 Jun 19  2021 cron.d\n"
        "-rw-r--r--  1 root root    191 Jun 19  2021 crontab\n"
        "-rw-r--r--  1 root root    611 Jun 19  2021 group\n"
        "-rw-r--r--  1 root root    221 Jun 19  2021 hosts\n"
        "-rw-r--r--  1 root root     13 Jun 19  2021 hostname\n"
        "-rw-r--r--  1 root root     27 Jun 19  2021 issue\n"
        "-rw-r--r--  1 root root   1682 Jun 19  2021 passwd\n"
        "-rw-r-----  1 root shadow  729 Jun 19  2021 shadow\n"
        "drwxr-xr-x  2 root root   4096 Jun 19  2021 ssh\n"
        "-r--r-----  1 root root    755 Jun 19  2021 sudoers\n"
        "-rw-r--r--  1 root root     13 Jun 19  2021 timezone\n"
    ),
    "/tmp": (
        "total 8\n"
        "drwxrwxrwt  2 root root 4096 Jun 19 08:42 .\n"
        "drwxr-xr-x 18 root root 4096 Jun 19  2021 ..\n"
    ),
}

# 與 ~/.bash_history 同源（fake_fs.STATIC_HISTORY_COMMANDS），編號 501 起
_STATIC_HISTORY = [
    f"  {i}  {cmd}" for i, cmd in enumerate(fake_fs.STATIC_HISTORY_COMMANDS, start=501)
]

class CacheHandler:
    def handle(self, command: str, current_dir: str, user: str,
               history: list[str] | None = None, attacker_ip: str = "") -> str | None:
        cmd = command.strip()

        # 一次性 sudo：sudo -l 給確定性授權清單;其餘讀取類指令以 root 身分執行,
        # 確保「sudo cat /etc/shadow」與提權後「cat /etc/shadow」拿到同一份內容。
        if cmd == "sudo -l" or cmd.startswith("sudo -l "):
            return self._sudo_l(user)
        if cmd.startswith("sudo ") and "-c" not in cmd.split():
            inner = cmd[len("sudo "):].strip()
            if inner and not inner.startswith("-"):
                return self.handle(inner, current_dir, "root", history, attacker_ip)

        if cmd == "pwd":
            return current_dir + "\n"

        if cmd == "whoami":
            return user + "\n"

        if cmd == "id":
            uid = _UID_MAP.get(user, 1000)
            gid = uid
            groups = f"{gid}({user})"
            if user in fake_fs.SUDO_NOPASSWD:   # 與 sudoers / sudo -l 一致
                groups += ",27(sudo)"
            return f"uid={uid}({user}) gid={gid}({user}) groups={groups}\n"

        if cmd == "hostname":
            return "web-server-01\n"

        if cmd in ("bash", "sh", "/bin/bash", "/bin/sh"):
            return "bash-4.4$ \n"

        if re.match(r"^(ss|netstat)\b", cmd):
            return self._network_status(cmd, attacker_ip)

        if re.match(r"^uname(\s+-\w+)*$", cmd):
            return "Linux web-server-01 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:52 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"

        if cmd == "date":
            return fake_fs.SYSTEM_DATE + "\n"

        if cmd == "uptime":
            return " 08:42:17 up 312 days, 14:03,  1 user,  load average: 0.08, 0.03, 0.01\n"

        if cmd == "history":
            lines = list(_STATIC_HISTORY)
            if history:
                for i, item in enumerate(history, start=514):
                    # item may be "$ cmd\nresp..." or just "cmd"
                    first_line = item.lstrip("$ ").splitlines()[0].strip()
                    lines.append(f"  {i}  {first_line}")
            return "\n".join(lines) + "\n"

        if re.match(r"^ls(\s+-\w+)*(\s+\S+)?$", cmd):
            parts = cmd.split()
            has_long = any("l" in p for p in parts if p.startswith("-"))
            raw_target = next((p for p in parts[1:] if not p.startswith("-")), None)
            target = fake_fs.normalize_path(current_dir, raw_target or ".")
            shown = raw_target or target

            known_dir = target in _LS_MAP or target in fake_fs.FAKE_DIRS
            known = known_dir or target in fake_fs.FAKE_FILES

            if has_long:
                long_out = _LS_LONG_MAP.get(target)
                if long_out is not None:
                    return long_out
                # 存在但沒有靜態長格式 → 交給 LLM；完全不存在 → 真實錯誤
                if known:
                    return None
                return f"ls: cannot access '{shown}': No such file or directory\n"

            listing = _LS_MAP.get(target)
            if listing is not None:
                return listing
            if known:
                return None  # 存在但沒有靜態清單 → 交給 LLM（會被 _dynamic_fs 快取）
            return f"ls: cannot access '{shown}': No such file or directory\n"

        if re.match(r"^cat\s+\S+$", cmd):
            path = cmd.split(maxsplit=1)[1]
            path = fake_fs.normalize_path(current_dir, path)
            return self._cat(path, user)

        return None  # cache miss

    def _sudo_l(self, user: str) -> str:
        if user == "root" or user in fake_fs.SUDO_NOPASSWD:
            return (
                f"Matching Defaults entries for {user} on web-server-01:\n"
                "    env_reset, mail_badpass,\n"
                "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
                f"User {user} may run the following commands on web-server-01:\n"
                "    (ALL) NOPASSWD: ALL\n"
            )
        return f"Sorry, user {user} may not run sudo on web-server-01.\n"

    def _network_status(self, cmd: str, attacker_ip: str = "") -> str:
        # 顯示「攻擊者自己的」SSH 連線而非寫死的無關連線（攻擊者能在輸出裡看到自己）
        peer = attacker_ip or "10.0.0.1"
        if cmd.startswith("ss"):
            return (
                "Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port  Process\n"
                "tcp    LISTEN  0       128      0.0.0.0:22           0.0.0.0:*           users:((\"sshd\",pid=1023,fd=3))\n"
                "tcp    LISTEN  0       511      0.0.0.0:80           0.0.0.0:*           users:((\"nginx\",pid=1456,fd=6))\n"
                "tcp    LISTEN  0       70       127.0.0.1:3306       0.0.0.0:*           users:((\"mysqld\",pid=1789,fd=21))\n"
                f"tcp    ESTAB   0       0        10.0.0.2:22          {peer}:54321      users:((\"sshd\",pid=3142,fd=4))\n"
            )
        # netstat
        return (
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1023/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1456/nginx\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      1789/mysqld\n"
            f"tcp        0    364 10.0.0.2:22             {peer}:54321          ESTABLISHED 3142/sshd\n"
        )

    # 公開可讀（644 之類）的誘餌檔；其餘私密檔走 fake_fs.PRIVATE_FILES 權限判斷
    _FILE_CONTENT = {
        "/etc/passwd": _ETC_PASSWD,
        "/etc/hosts": _ETC_HOSTS,
        "/proc/version": _PROC_VERSION,
        "/var/www/html/.env": _BAIT_ENV,
        "/var/www/html/wp-config.php": fake_fs.WP_CONFIG,
        "/home/admin/backup.sql": fake_fs.BACKUP_SQL,
        "/etc/shadow": fake_fs.ETC_SHADOW,
        "/etc/sudoers": fake_fs.ETC_SUDOERS,
        "/var/log/auth.log": fake_fs.AUTH_LOG,
        "/home/dbadmin/.my.cnf": fake_fs.MY_CNF,
        "/home/admin/.bash_history": fake_fs.ADMIN_BASH_HISTORY,
    }

    def _cat(self, path: str, user: str) -> str | None:
        content = self._FILE_CONTENT.get(path)
        if content is None:
            return None  # cache miss → LLM handles unknown paths
        if not fake_fs.can_read(path, user):
            return f"cat: {path}: Permission denied\n"
        return content
