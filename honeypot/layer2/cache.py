import re

_ETC_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:admin,,,:/home/admin:/bin/bash
deploy:x:1001:1001::/home/deploy:/bin/bash
backup:x:1002:1002::/home/backup:/bin/sh
dbadmin:x:1003:1003::/home/dbadmin:/bin/bash
"""

_ETC_HOSTS = """\
127.0.0.1\tlocalhost
127.0.1.1\tweb-server-01
10.0.0.5\tdb-internal
10.0.0.10\tbackup-server
"""

_BAIT_ENV = """\
APP_ENV=production
APP_KEY=base64:3lV7kQmN2pXwR8sT1uYvZaB4cDeF6gHi
DB_HOST=localhost
DB_DATABASE=ecommerce_db
DB_USERNAME=dbadmin
DB_PASSWORD=Sup3rS3cr3t!2019
MAIL_HOST=smtp.mailgun.org
MAIL_PASSWORD=mg_smtp_pass_2019
AWS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

_PROC_VERSION = "Linux version 4.15.0-213-generic (buildd@lcy02-amd64-013) (gcc version 7.5.0 (Ubuntu 7.5.0-3ubuntu1~18.04)) #224-Ubuntu SMP Mon Jun 19 13:30:52 UTC 2023\n"

_LS_MAP = {
    "/":              "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  srv  sys  tmp  usr  var\n",
    "/etc":           "cron.d  crontab  group  hosts  hostname  issue  passwd  shadow  ssh  sudoers  timezone\n",
    "/home":          "admin  backup  dbadmin  deploy\n",
    "/home/admin":    ".bash_history  .bashrc  .profile  backup.sql\n",
    "/var/www/html":  ".env  index.php  wp-config.php  wp-admin  wp-content  wp-includes\n",
    "/tmp":           "\n",
    "/var/www":       "html\n",
    "/var":           "backups  cache  lib  log  mail  opt  run  spool  www\n",
    "/proc":          "1  cpuinfo  meminfo  net  version\n",
    "/opt":           "\n",
    "/usr/bin":       "awk  bash  cat  curl  find  grep  ls  python3  ssh  tar  wget\n",
}

class CacheHandler:
    def handle(self, command: str, current_dir: str, user: str) -> str | None:
        cmd = command.strip()

        if cmd == "pwd":
            return current_dir + "\n"

        if cmd == "whoami":
            return user + "\n"

        if cmd == "id":
            uid = 0 if user == "root" else 1000
            gid = uid
            return f"uid={uid}({user}) gid={gid}({user}) groups={gid}({user})\n"

        if cmd == "hostname":
            return "web-server-01\n"

        if re.match(r"^uname(\s+-\w+)*$", cmd):
            return "Linux web-server-01 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:52 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"

        if cmd == "date":
            return "Mon Jun 19 08:42:17 UTC 2023\n"

        if cmd == "uptime":
            return " 08:42:17 up 312 days, 14:03,  1 user,  load average: 0.08, 0.03, 0.01\n"

        if re.match(r"^ls(\s+-\w+)*(\s+\S+)?$", cmd):
            parts = cmd.split()
            target = None
            for p in parts[1:]:
                if not p.startswith("-"):
                    target = p if p.startswith("/") else (current_dir.rstrip("/") + "/" + p)
                    break
            target = target or current_dir
            return _LS_MAP.get(target, "ls: cannot access '" + target + "': No such file or directory\n")

        if re.match(r"^cat\s+\S+$", cmd):
            path = cmd.split(maxsplit=1)[1]
            if not path.startswith("/"):
                path = current_dir.rstrip("/") + "/" + path
            return self._cat(path)

        if re.match(r"^echo\s+.*$", cmd):
            return cmd.split(maxsplit=1)[1].strip('"\'') + "\n"

        return None  # cache miss

    def _cat(self, path: str) -> str:
        if path == "/etc/passwd":
            return _ETC_PASSWD
        if path == "/etc/hosts":
            return _ETC_HOSTS
        if path == "/proc/version":
            return _PROC_VERSION
        if path == "/var/www/html/.env":
            return _BAIT_ENV
        if path == "/etc/shadow":
            return "cat: /etc/shadow: Permission denied\n"
        if path == "/etc/sudoers":
            return "cat: /etc/sudoers: Permission denied\n"
        if path in ("/home/admin/backup.sql", "/home/admin/.bash_history",
                    "/var/www/html/wp-config.php"):
            return self._cat_interesting(path)
        if path == "/var/log/auth.log":
            return ("May 29 08:12:01 web-server-01 sshd[1234]: Failed password for root from 185.220.101.45 port 54321 ssh2\n"
                    "May 29 08:12:03 web-server-01 sshd[1235]: Failed password for admin from 185.220.101.45 port 54322 ssh2\n"
                    "May 29 08:12:05 web-server-01 sshd[1236]: Accepted password for root from 192.168.1.10 port 22 ssh2\n"
                    "May 29 09:33:12 web-server-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash\n"
                    "May 29 10:01:44 web-server-01 sshd[2341]: Failed password for root from 45.33.32.156 port 12345 ssh2\n")
        return f"cat: {path}: No such file or directory\n"

    def _cat_interesting(self, path: str) -> str:
        if path == "/home/admin/backup.sql":
            return ("-- MySQL dump 10.13  Distrib 5.7.42\n"
                    "-- Host: localhost    Database: ecommerce_db\n"
                    "CREATE DATABASE ecommerce_db;\nUSE ecommerce_db;\n"
                    "INSERT INTO users VALUES (1,'admin','$2y$10$abcdefghijk...');\n")
        if path == "/home/admin/.bash_history":
            return ("ls\ncd /var/www/html\ncat .env\nmysql -u dbadmin -pSup3rS3cr3t!2019 ecommerce_db\n"
                    "sudo systemctl restart nginx\ntail -f /var/log/nginx/error.log\n")
        if path == "/var/www/html/wp-config.php":
            return ("<?php\ndefine('DB_NAME','ecommerce_db');\n"
                    "define('DB_USER','dbadmin');\ndefine('DB_PASSWORD','Sup3rS3cr3t!2019');\n"
                    "define('DB_HOST','localhost');\n")
        return ""
