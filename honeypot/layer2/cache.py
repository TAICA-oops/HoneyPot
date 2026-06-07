import re
from shared import fake_fs
from layer2 import overlay

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

        # 寫入類指令（echo>檔案、mkdir、touch、useradd、rm…）：更新可變狀態覆寫層,
        # 讓之後（含重連/跨程序）的讀取都反映這些變更。
        written = overlay.apply_write(cmd, current_dir, user)
        if written is not None:
            return written

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
            return fake_fs.date_str() + "\n"

        if cmd == "uptime":
            return fake_fs.uptime_str() + "\n"

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

            if overlay.is_deleted(target):
                return f"ls: cannot access '{shown}': No such file or directory\n"

            extra = overlay.list_extra(target)
            deleted = overlay.deleted_names(target)
            known_dir = target in _LS_MAP or target in fake_fs.FAKE_DIRS or overlay.is_dir(target)
            known = known_dir or target in fake_fs.FAKE_FILES

            if has_long:
                long_out = _LS_LONG_MAP.get(target)
                if long_out is not None:
                    return self._merge_long(long_out, extra, deleted, target)
                if extra or overlay.is_dir(target):
                    return self._merge_long("", extra, deleted, target)
                if known:
                    return None
                return f"ls: cannot access '{shown}': No such file or directory\n"

            listing = _LS_MAP.get(target)
            if listing is not None or extra or deleted or overlay.is_dir(target):
                base_names = listing.split() if listing else []
                names = [n for n in base_names if n not in deleted]
                names += [n for n in extra if n not in names]
                return ("  ".join(sorted(names)) + "\n") if names else "\n"
            if known:
                return None  # 存在但沒有靜態清單 → 交給 LLM（會被 _dynamic_fs 快取）
            return f"ls: cannot access '{shown}': No such file or directory\n"

        if re.match(r"^cat\s+\S+$", cmd):
            path = cmd.split(maxsplit=1)[1]
            path = fake_fs.normalize_path(current_dir, path)
            return self._cat(path, user)

        if re.match(r"^(head|tail)\b", cmd):
            return self._head_tail(cmd, current_dir, user)

        if re.match(r"^wc\b", cmd):
            return self._wc(cmd, current_dir, user)

        if re.match(r"^grep\b", cmd):
            return self._grep(cmd, current_dir, user)

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

    def _resolve(self, path: str, user: str) -> tuple[str, str | None]:
        """解析檔案內容,覆寫層優先。回傳 (status, content)；
        status ∈ {'ok','deleted','denied','unknown'}。"""
        row = overlay.lookup(path)                 # 單次查詢取代 is_deleted+read_file
        if row is not None:
            kind, content = row
            if kind == "deleted":
                return "deleted", None
            if kind == "file":
                if not fake_fs.can_read(path, user):
                    return "denied", None
                return "ok", content
        base = self._FILE_CONTENT.get(path)
        if base is None:
            return "unknown", None
        if not fake_fs.can_read(path, user):
            return "denied", None
        return "ok", base

    def _merge_long(self, base_long: str, extra: list[str], deleted: set[str], dir_path: str) -> str:
        lines = []
        for ln in base_long.splitlines():
            name = ln.rsplit(" ", 1)[-1]
            if name in deleted:
                continue
            lines.append(ln)
            extra = [e for e in extra if e != name]
        date = fake_fs.now_utc().strftime("%b %e %H:%M")
        base = dir_path.rstrip("/")
        for name in extra:
            full = f"{base}/{name}"
            if overlay.is_dir(full):
                lines.append(f"drwxr-xr-x 2 root root 4096 {date} {name}")
            else:
                content = overlay.read_file(full)
                size = len(content.encode()) if content else 0
                lines.append(f"-rw-r--r-- 1 root root {size:>5} {date} {name}")
        return ("\n".join(lines) + "\n") if lines else "total 0\n"

    def _cat(self, path: str, user: str) -> str | None:
        status, content = self._resolve(path, user)
        if status == "ok":
            return content
        if status == "deleted":
            return f"cat: {path}: No such file or directory\n"
        if status == "denied":
            return f"cat: {path}: Permission denied\n"
        return None  # unknown → LLM

    def _head_tail(self, cmd: str, current_dir: str, user: str) -> str | None:
        parts = cmd.split()
        kind = parts[0]              # head | tail
        n, file_tok, i = 10, None, 1
        while i < len(parts):
            p = parts[i]
            if p == "-n" and i + 1 < len(parts):
                try:
                    n = int(parts[i + 1])
                except ValueError:
                    return None
                i += 2
                continue
            if re.fullmatch(r"-\d+", p):
                n = int(p[1:])
            elif not p.startswith("-"):
                file_tok = p
            i += 1
        if file_tok is None:
            return None              # 從 stdin 讀 → 交給 LLM
        path = fake_fs.normalize_path(current_dir, file_tok)
        status, content = self._resolve(path, user)
        if status == "unknown":
            return None
        if status == "deleted":
            return f"{kind}: cannot open '{path}' for reading: No such file or directory\n"
        if status == "denied":
            return f"{kind}: cannot open '{path}' for reading: Permission denied\n"
        lines = content.splitlines()
        chosen = lines[:n] if kind == "head" else lines[-n:]
        return ("\n".join(chosen) + "\n") if chosen else ""

    def _grep(self, cmd: str, current_dir: str, user: str) -> str | None:
        import shlex
        try:
            toks = shlex.split(cmd, posix=True)   # 保留含空白的引號樣式
        except ValueError:
            toks = cmd.split()
        flags, positional = set(), []
        for t in toks[1:]:
            if t.startswith("-") and len(t) > 1 and not t[1:].isdigit():
                flags.update(t[1:])
            else:
                positional.append(t)
        # 遞迴 grep 或多檔交給 LLM；單檔才確定性處理
        if "r" in flags or "R" in flags or len(positional) != 2:
            return None
        pattern, file_tok = positional
        pattern = pattern.strip("'\"")
        path = fake_fs.normalize_path(current_dir, file_tok)
        status, content = self._resolve(path, user)
        if status == "unknown":
            return None
        if status == "deleted":
            return f"grep: {path}: No such file or directory\n"
        if status == "denied":
            return f"grep: {path}: Permission denied\n"
        flags_re = re.IGNORECASE if "i" in flags else 0
        out = []
        for idx, line in enumerate(content.splitlines(), start=1):
            try:
                matched = re.search(pattern, line, flags_re) is not None
            except re.error:
                matched = pattern in line
            if "v" in flags:
                matched = not matched
            if matched:
                out.append(f"{idx}:{line}" if "n" in flags else line)
        return ("\n".join(out) + "\n") if out else ""

    def _wc(self, cmd: str, current_dir: str, user: str) -> str | None:
        parts = cmd.split()
        mode, file_tok = None, None
        for p in parts[1:]:
            if p in ("-c", "-l", "-w", "-m"):
                mode = p[1]
            elif not p.startswith("-"):
                file_tok = p
        if file_tok is None:
            return None
        path = fake_fs.normalize_path(current_dir, file_tok)
        status, content = self._resolve(path, user)
        if status == "unknown":
            return None
        if status == "deleted":
            return f"wc: {path}: No such file or directory\n"
        if status == "denied":
            return f"wc: {path}: Permission denied\n"
        nb, nl, nw = len(content.encode()), content.count("\n"), len(content.split())
        if mode in ("c", "m"):
            return f"{nb} {path}\n"
        if mode == "l":
            return f"{nl} {path}\n"
        if mode == "w":
            return f"{nw} {path}\n"
        return f"{nl} {nw} {nb} {path}\n"
