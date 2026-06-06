# CLAUDE.md

## Project Layout

All Python code lives under `honeypot/`. The virtualenv is at `honeypot/.venv/`.

```
honeypot/
  layer1/   SSH + HTTP honeypot servers, logger, session manager
  layer2/   FastAPI LLM engine (cache → Ollama → intent classifier)
  layer3/   Stats API (FastAPI) + React frontend
  tests/    mirrors layer structure
  .env      all config (ports, model name, DB path)
  honeypot.db  SQLite, shared by all layers
```

## Commit Convention

Write commit messages in **Traditional Chinese** using the Conventional Commits format:

```
<type>(<optional scope>): <subject>

<optional body>
```

Types: `feat` | `fix` | `docs` | `chore` | `refactor` | `test`


## Commands

```bash
cd honeypot

# 第一次設定（建 venv 後必須跑，否則 import 會失敗）
pip install -e .

# tests
.venv/bin/pytest tests/ -v

# run all services
./scripts/start.sh

# individual services
.venv/bin/uvicorn layer2.main:app --port 8000 --reload
.venv/bin/uvicorn layer3.stats_api:app --port 8001 --reload
.venv/bin/python layer1/ssh_server.py
.venv/bin/python layer1/http_server.py

# frontend
cd layer3/frontend && npm run dev
```

## Critical Architecture Facts

**Layer 1 owns all session state** — `session_manager.py` owns `current_dir` AND the privilege stack (`user_stack`). `cd` is handled entirely in Layer 1 (never sent to Layer 2). Privilege escalation that opens a *persistent* shell (`sudo su`, `sudo -i`, `sudo bash`) is detected by `detect_escalation()`; `push_user`/`pop_user` track the effective user so `whoami`/`id`/file permissions stay consistent, and `exit`/Ctrl-D unwind one level at a time. LLM never manages state.

**Cache-first** — `layer2/cache.py` handles common commands (ls, cat, whoami, pwd, id, uname, echo, ss/netstat, history, sudo -l) without calling Ollama. Returns `None` on cache miss → goes to Ollama. `cache.handle()` takes `user` (effective user) and `attacker_ip`. Paths are normalised via `fake_fs.normalize_path` so `cd`/`ls` agree on what exists (every dir `ls` shows is `cd`-able). One-shot `sudo <read-cmd>` is re-run as root inside the cache so it matches a post-escalation read.

**Permission model** — `fake_fs.can_read(path, user)`: private files in `fake_fs.PRIVATE_FILES` (shadow, sudoers, `.my.cnf`, others' `.bash_history`) are readable only by their owner and root. `cache._cat` enforces this; root reads everything.

**Two models** — `OLLAMA_MODEL` for terminal responses (low temperature=0.1), `OLLAMA_REPORT_MODEL` for threat reports (temperature=0.6). Both in `.env`. `ollama_client.py` reads both at call time.

**DB_PATH env var** — `layer2/db.py` reads `DB_PATH` from environment. Tests override it via the `tmp_db` fixture in `tests/conftest.py`. Never hardcode the DB path.

**`get_conn()` with no args** reads `DB_PATH` from env. All three layers share the same `honeypot.db` via this mechanism.

**Fake filesystem (single source of truth)** — bait file contents, `/etc/passwd`+`/etc/shadow`, the UID map, home dirs, the `FAKE_DIRS`/`FAKE_FILES` sets, the frozen `SYSTEM_DATE`, and the sudoers config all live in `shared/fake_fs.py`. `layer2/cache.py`, `layer1/http_server.py` (`/.env`), and `layer2/prompt_builder.py` (KNOWN FILES / FILESYSTEM blocks) all import from it — never duplicate bait content. The LLM prompt embeds the canonical directory tree + users + frozen time so cache-miss responses stay consistent with the cache.

**SSH protocol** — paramiko server offers RSA + ECDSA host keys. Both interactive shells (`check_channel_shell_request`) and non-interactive `ssh host 'cmd'` (`check_channel_exec_request` → `_handle_exec`) are supported.

**HTTP server** — requests from one IP aggregate into a single `session_id` (`http-<ip>`); `logger.session_touch` keeps the highest threat level seen. Intent classifier runs on path+body (phpMyAdmin POST bodies are URL-decoded so `sql_query` is captured), result logged to both `http_requests` and `commands`.

**WebSocket broadcast** — `logger.py` calls `enqueue_event(event)` (thread-safe sync). `stats_api.py` runs a background task on the ASGI loop that consumes the queue and calls `broadcast()`. Never call `broadcast()` directly from non-async code.

## Intent Categories

`reconnaissance`, `privilege_escalation`, `data_exfiltration`, `persistence`, `lateral_movement`, `credential_harvesting`, `web_recon`, `injection_attempt`, `unknown`

Threat level logic in `ssh_server.py:_compute_threat_level()`:
- Critical: privilege_escalation AND data_exfiltration both seen
- High: privilege_escalation OR data_exfiltration seen
- Medium: persistence or lateral_movement seen
- Low: everything else

**shared/models.py** — single source of truth for `RespondRequest`/`RespondResponse` Pydantic models. `VALID_INTENTS` must be updated whenever `intent_classifier.py` adds new intent categories.

## Adding a New Fake File

1. Add the content constant to `shared/fake_fs.py`
2. Map the path → content in `CacheHandler._FILE_CONTENT` (`layer2/cache.py`)
3. Add the filename to the relevant `_LS_MAP` / `_LS_LONG_MAP` entry, and the path to `fake_fs.FAKE_FILES`
4. If it should be private (owner-only), add `path → owner` to `fake_fs.PRIVATE_FILES`
5. For a new directory, add it to `fake_fs.FAKE_DIRS` and give it an `_LS_MAP` listing
