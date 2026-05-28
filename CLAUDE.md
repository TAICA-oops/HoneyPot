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

**Layer 1 handles `cd` entirely** — never sends `cd` to Layer 2. `session_manager.py` owns `current_dir` state. LLM never manages state.

**Cache-first** — `layer2/cache.py` handles common commands (ls, cat, whoami, pwd, id, uname, echo) without calling Ollama. Returns `None` on cache miss → goes to Ollama.

**Two models** — `OLLAMA_MODEL` for terminal responses (low temperature=0.1), `OLLAMA_REPORT_MODEL` for threat reports (temperature=0.6). Both in `.env`. `ollama_client.py` reads both at call time.

**DB_PATH env var** — `layer2/db.py` reads `DB_PATH` from environment. Tests override it via the `tmp_db` fixture in `tests/conftest.py`. Never hardcode the DB path.

**`get_conn()` with no args** reads `DB_PATH` from env. All three layers share the same `honeypot.db` via this mechanism.

**Fake filesystem** — bait files are in `layer2/cache.py`: `/var/www/html/.env`, `/home/admin/backup.sql`, `/var/www/html/wp-config.php`. Edit there to change what attackers find.

**HTTP server** — each request creates a new `session_id` (IP + uuid4). Intent classifier runs on path+body, result logged to both `http_requests` and `commands` table. Session immediately ends after logging.

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

1. Add content string to `layer2/cache.py`
2. Add a branch in `CacheHandler._cat()` for the path
3. Add the filename to the relevant `_LS_MAP` entry
