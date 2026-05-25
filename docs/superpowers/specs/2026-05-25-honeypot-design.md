# LLM-Powered Honeypot — Design Spec

**Date:** 2026-05-25
**Course:** 大型語言模型與資訊安全系統
**Type:** High-interaction honeypot (LLM Tarpit)

---

## Overview

A three-layer LLM-driven honeypot that traps attackers in a believable fake Ubuntu 18.04 e-commerce server (SSH) and a fake WordPress site (HTTP). All attacker interactions are logged to SQLite, classified by intent, and surfaced on a real-time React dashboard with auto-generated threat intelligence reports.

---

## Architecture

**FastAPI microservices** — Layer 1 and Layer 2 are separate processes communicating via HTTP POST. This matches the JSON interface defined in the spec and lets each layer be developed and restarted independently. Layer 3's stats API reads the shared SQLite file and serves a React frontend deployed to Vercel.

```
Attacker
  │
  ├─ SSH :2222 ──┐
  └─ HTTP :8080 ─┤
                 │
           [Layer 1 — Honeypot Server]
           ssh_server.py / http_server.py
           session_manager.py (state)
           llm_client.py (HTTP POST to L2)
           logger.py (SQLite writes)
                 │
                 │ POST /respond (JSON)
                 ▼
           [Layer 2 — LLM Engine :8000]
           cache.py (rule-based, fast)
           ollama_client.py (streaming)
           intent_classifier.py
           prompt_builder.py
           db.py
                 │
                 │ SQLite reads
                 ▼
           [Layer 3 — Intelligence :8001]
           stats_api.py (FastAPI)
           report_generator.py
           frontend/ (React + Vite → Vercel)
```

**Shared state:** All three layers share one `honeypot.db` SQLite file on the same machine (glows.ai). No Redis or message queue needed.

---

## Directory Structure

```
honeypot/
  layer1/
    ssh_server.py          # paramiko SSH server, port 2222
    http_server.py         # FastAPI HTTP honeypot, port 8080
    session_manager.py     # maintains current_dir, user, history per session
    llm_client.py          # HTTP client to POST to Layer 2
    logger.py              # writes sessions/commands/http_requests to SQLite
  layer2/
    main.py                # FastAPI app, POST /respond
    cache.py               # rule-based handler for common commands
    prompt_builder.py      # builds system prompt with Ubuntu 18.04 persona
    ollama_client.py       # Ollama streaming client, model from config
    intent_classifier.py   # keyword classifier + LLM fallback
    db.py                  # SQLite schema init and query helpers
  layer3/
    stats_api.py           # FastAPI read-only API, port 8001
    report_generator.py    # reads session from SQLite, calls LLM for Markdown report
    frontend/              # React + Vite
      src/
        pages/
          Dashboard.tsx    # live feed + stats
          Sessions.tsx     # session list + replay
          Reports.tsx      # rendered Markdown reports
        components/
          LiveFeed.tsx     # WebSocket attacker command stream
          IntentChart.tsx  # intent distribution pie chart
          CommandChart.tsx # top commands bar chart
  honeypot.db              # shared SQLite database
  .env                     # all config (model, ports, etc.)
  docker-compose.yml       # runs Layer 1 + Layer 2 + Layer 3 backend together
```

---

## Configuration (.env)

```env
# Switch model by changing this one line
OLLAMA_MODEL=llama3.1
OLLAMA_HOST=http://localhost:11434

SSH_PORT=2222
HTTP_PORT=8080
LLM_ENGINE_PORT=8000
STATS_API_PORT=8001

DB_PATH=./honeypot.db
SESSION_TIMEOUT_SECONDS=600
```

---

## Layer 1 — Honeypot Server

### SSH Server (`ssh_server.py`)

- Uses `paramiko` to run a fake SSH server on port 2222
- Authentication: always returns success regardless of credentials
- Banner: `Ubuntu 18.04.6 LTS` to match the persona
- Per-connection session state managed by `session_manager.py`
- Streams LLM response back char-by-char (simulates a slow old server)
- Triggers report generation on `exit` command or timeout

### Session Manager (`session_manager.py`)

- Maintains per-session state in memory: `current_dir`, `user`, `history` (last 10 commands)
- Handles `cd` locally (updates `current_dir`) before sending to Layer 2
- Does not let LLM manage state — LLM only does text generation

### HTTP Server (`http_server.py`)

Simulates a vulnerable WordPress site. All routes return believable HTML:

| Method | Path | Response |
|--------|------|----------|
| GET | /wp-admin | Fake WP login page (200) |
| GET | /wp-login.php | Fake login form (200) |
| POST | /wp-login.php | Log harvested credentials + fake login failure |
| GET | /.env | Fake .env with DB credentials (200) — bait file |
| GET | /phpmyadmin | Fake phpMyAdmin login (200) |
| GET | /xmlrpc.php | Fake XML-RPC endpoint (200) |
| GET | * | Fake 404 in WordPress style |

### Logger (`logger.py`)

Writes every interaction to SQLite immediately after Layer 2 responds.

---

## Layer 2 — LLM Engine

### API Endpoint

```
POST /respond
Content-Type: application/json
```

**Request:**
```json
{
  "session_id": "abc123",
  "protocol": "ssh",
  "command": "cat /etc/passwd",
  "current_dir": "/etc",
  "user": "admin",
  "history": ["whoami", "ls -la", "cd /etc"]
}
```

**Response:**
```json
{
  "session_id": "abc123",
  "response": "root:x:0:0:root:/root:/bin/bash\n...",
  "intent": "reconnaissance",
  "confidence": 0.87,
  "cache_hit": false
}
```

### Cache (`cache.py`)

Keyword-based fast path for common Linux commands. Returns pre-defined fake filesystem output without calling Ollama. Covers: `ls`, `pwd`, `whoami`, `id`, `uname -a`, `hostname`, `date`, `uptime`, `ps aux`, `netstat`, `cat /etc/passwd`, `cat /etc/hosts`, `cat /proc/version`.

Fake filesystem root includes: `/home/admin/backup.sql`, `/var/www/html/.env`, `/var/log/auth.log` — designed to tempt attackers into deeper exploration.

### Intent Classifier (`intent_classifier.py`)

Two-stage:
1. **Keyword match** (fast, handles ~80% of cases) — maps command patterns to intent categories
2. **LLM fallback** for ambiguous commands only

Intent categories:

| Intent | Trigger Examples |
|--------|-----------------|
| `reconnaissance` | ls, cat, find, grep, whoami, id, uname, ps, netstat |
| `privilege_escalation` | sudo, su, chmod 777, /etc/sudoers, SUID find |
| `data_exfiltration` | curl, wget, scp, nc, base64, /etc/shadow |
| `persistence` | crontab, ~/.bashrc, authorized_keys, systemctl |
| `lateral_movement` | ssh, ping, nmap, /etc/hosts, arp |
| `web_recon` | HTTP path scanning, User-Agent analysis |
| `credential_harvesting` | POST to /wp-login.php with body |
| `injection_attempt` | SQL/command injection patterns in HTTP body |

### LLM Persona (System Prompt)

Ubuntu 18.04 LTS e-commerce backend server, old and misconfigured:

- Has realistic fake sensitive files with plausible content
- `/etc/passwd` includes fake accounts: `deploy`, `backup`, `dbadmin`
- `sudo -l` output suggests misconfigured sudoers (tempts privilege escalation attempts)
- LLM does not track state — `current_dir` is always injected into the prompt by Layer 1
- Responses use streaming to simulate network latency on an old machine
- Ollama model is read from `OLLAMA_MODEL` env var — can be swapped without code changes

---

## Layer 3 — Intelligence & Dashboard

### Stats API (`stats_api.py`)

Read-only FastAPI on port 8001. Endpoints:

```
GET /api/sessions          # list all sessions with metadata
GET /api/sessions/{id}     # full command history for a session
GET /api/stats/intents     # intent distribution counts
GET /api/stats/commands    # top N most-used commands
GET /api/stats/timeline    # commands per hour
GET /api/reports/{id}      # get generated report for a session
WS  /ws/live               # WebSocket: push new commands in real time
```

### Report Generator (`report_generator.py`)

Triggered when a session ends. Reads all commands for the session from SQLite, builds a prompt, calls Ollama, and saves the Markdown result back to the DB.

Report sections:
1. Executive Summary
2. Attack Timeline (each command with timestamp and intent)
3. Intent Analysis (distribution and interpretation)
4. Indicators of Compromise (IoCs)
5. Threat Level: Low / Medium / High / Critical

### Frontend (React + Vite)

Four pages:
- **Dashboard** — live WebSocket feed showing attacker commands as they happen; intent distribution pie chart; SSH vs HTTP stats; active sessions count
- **Sessions** — list of all past sessions with threat level badge; click to replay full timeline
- **Reports** — rendered Markdown threat intelligence reports per session
- **Settings** — current model name, ports, session count (read from `/api/config`)

Deployed to Vercel. Points to the stats API URL via `VITE_API_URL` env var.

---

## Database Schema

```sql
CREATE TABLE sessions (
  session_id   TEXT PRIMARY KEY,
  protocol     TEXT,           -- 'ssh' or 'http'
  attacker_ip  TEXT,
  start_time   DATETIME,
  end_time     DATETIME,
  total_cmds   INTEGER DEFAULT 0,
  threat_level TEXT,           -- Low / Medium / High / Critical
  report       TEXT            -- generated Markdown, nullable
);

CREATE TABLE commands (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id   TEXT,
  timestamp    DATETIME,
  command      TEXT,
  response     TEXT,
  intent       TEXT,
  confidence   REAL,
  cache_hit    BOOLEAN
);

CREATE TABLE http_requests (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id       TEXT,
  timestamp        DATETIME,
  method           TEXT,
  path             TEXT,
  body             TEXT,
  response_code    INTEGER,
  harvested_creds  TEXT        -- JSON string of extracted credentials, nullable
);
```

---

## Error Handling

- **Ollama timeout:** If Ollama doesn't respond within 10 seconds, Layer 2 returns a generic `command not found` response so the SSH session doesn't hang
- **SQLite write failure:** Log to stderr, continue serving the attacker (don't let logging break the honeypot)
- **Layer 2 unreachable:** Layer 1 falls back to cache-only mode, serving only rule-based responses
- **Session timeout:** After `SESSION_TIMEOUT_SECONDS` of inactivity, session is closed and report generated

---

## Testing Strategy

- **Layer 2 in isolation:** Start the FastAPI server, POST crafted JSON payloads, assert response shape and intent label — no SSH needed
- **SSH smoke test:** `ssh -p 2222 anyuser@localhost` with any password, run a few commands, assert they get responses
- **HTTP smoke test:** `curl localhost:8080/wp-admin`, assert HTML contains login form
- **Cache test:** Send `ls`, `whoami`, `pwd` — assert `cache_hit: true` in response
- **Intent test:** Send known-bad commands, assert intent labels match expected categories
- **End-to-end demo script:** `scripts/demo.sh` — connects via SSH, runs a canned attack sequence (recon → privilege escalation attempt → exfil attempt), prints the generated report at the end

---

## Milestones

| Week | Goal |
|------|------|
| 14 | Layer 1 SSH working (paramiko, any-password auth, basic command passthrough); Layer 2 FastAPI responding to POST with Ollama |
| 15 | Cache layer + intent classifier; HTTP honeypot (WordPress persona); SQLite logging; report generator |
| 16 | React dashboard (live feed + charts); Vercel deploy; end-to-end demo script; final report |
