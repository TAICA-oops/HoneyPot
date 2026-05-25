# LLM-Powered Honeypot

A high-interaction honeypot that traps attackers inside a believable fake Linux server and WordPress site, driven by a local LLM. Every command is classified by attack intent, logged to SQLite, and surfaced on a real-time React dashboard with auto-generated threat intelligence reports.

---

## How It Works

```
Attacker
  ├─ SSH :2222 ──┐
  └─ HTTP :8080 ─┤
                 ▼
         Layer 1 — Honeypot Servers
         (session state, logging, streaming)
                 │ POST /respond
                 ▼
         Layer 2 — LLM Engine :8000
         (rule-based cache → Ollama → intent classifier)
                 │ SQLite
                 ▼
         Layer 3 — Dashboard :8001 + Vercel
         (live feed, stats, threat reports)
```

**SSH persona:** Ubuntu 18.04.6 LTS e-commerce server. Any username/password succeeds. Common commands (ls, cat, pwd) return instantly from a rule-based cache with a fake filesystem containing bait files — `/var/www/html/.env` with fake DB credentials, `/home/admin/backup.sql`, and a misconfigured sudoers file. Unknown commands go to the LLM.

**HTTP persona:** Fake WordPress site. Responds to `/wp-admin`, `/wp-login.php` (logs harvested credentials), `/.env` (bait file), `/phpmyadmin`, `/xmlrpc.php`, and all other paths with a styled 404.

**Intent classifier:** Keyword-based, classifies commands into `reconnaissance`, `privilege_escalation`, `data_exfiltration`, `persistence`, `lateral_movement`. Fast path handles 80%+ of cases without LLM.

**Reports:** Auto-generated at session end — Executive Summary, Attack Timeline, IoCs, Threat Level (Low/Medium/High/Critical).

---

## Requirements

- Python 3.10+
- [Ollama](https://ollama.ai) running locally or on a remote server
- Node.js 18+ (for the React dashboard)

---

## Quick Start

### 1. Install Python dependencies

```bash
cd honeypot
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

Edit `honeypot/.env`:

```env
OLLAMA_MODEL=llama3.1        # any model Ollama supports
OLLAMA_HOST=http://localhost:11434
SSH_PORT=2222
HTTP_PORT=8080
LLM_ENGINE_PORT=8000
STATS_API_PORT=8001
DB_PATH=./honeypot.db
SESSION_TIMEOUT_SECONDS=600
```

Pull your chosen model:
```bash
ollama pull llama3.1
```

### 3. Start all services

```bash
cd honeypot
./scripts/start.sh
```

This starts Layer 2 (LLM engine), Layer 3 (stats API), Layer 1 SSH, and Layer 1 HTTP in the background. Press `Ctrl+C` to stop all.

### 4. Start the dashboard

```bash
cd honeypot/layer3/frontend
npm install
npm run dev        # http://localhost:5173
```

---

## Testing the Honeypot

Connect via SSH (any credentials work):
```bash
ssh -p 2222 anyuser@localhost
```

Scan with HTTP tools:
```bash
curl http://localhost:8080/wp-admin
curl http://localhost:8080/.env
curl -X POST http://localhost:8080/wp-login.php -d "log=admin&pwd=secret"
```

Run the automated demo attack:
```bash
./scripts/demo.sh
```

---

## Dashboard

| Page | Content |
|---|---|
| Dashboard | Live WebSocket feed of attacker commands, intent distribution chart, session stats |
| Sessions | Full session list with replay — click any session to see every command and response |
| Reports | LLM-generated Markdown threat intelligence report per session |

---

## Architecture Details

### File Structure

```
honeypot/
  layer1/
    ssh_server.py          # paramiko SSH server
    http_server.py         # FastAPI WordPress honeypot
    session_manager.py     # per-session state (current_dir, history)
    llm_client.py          # HTTP client to Layer 2
    logger.py              # SQLite writer
  layer2/
    main.py                # FastAPI POST /respond
    cache.py               # rule-based command handler + fake filesystem
    intent_classifier.py   # keyword-based intent classification
    prompt_builder.py      # Ubuntu 18.04 system prompt
    ollama_client.py       # Ollama HTTP client, streaming
    db.py                  # SQLite schema + connection
  layer3/
    stats_api.py           # read-only FastAPI + WebSocket /ws/live
    report_generator.py    # LLM Markdown report writer
    frontend/              # React + Vite → Vercel
  honeypot.db              # shared SQLite database
  .env                     # all configuration
  scripts/
    start.sh               # start all services locally
    demo.sh                # simulated attack for demo
```

### JSON Interface (Layer 1 → Layer 2)

```json
// Request
{ "session_id": "abc123", "protocol": "ssh", "command": "cat /etc/passwd",
  "current_dir": "/etc", "user": "admin", "history": ["whoami", "ls"] }

// Response
{ "session_id": "abc123", "response": "root:x:0:0...", 
  "intent": "reconnaissance", "confidence": 0.95, "cache_hit": false }
```

### Switching Models

Change one line in `.env`:
```env
OLLAMA_MODEL=gemma3        # or mistral, phi4, deepseek-r1, etc.
```

No code changes needed.

---

## Docker

```bash
cd honeypot
docker compose up
```

Note: Ollama must be reachable from containers. Set `OLLAMA_HOST` in `.env` to your host's address (e.g., `http://host.docker.internal:11434` on macOS).

---

## Vercel Deployment (Dashboard)

1. Set `OLLAMA_HOST` in `.env` to a publicly reachable URL
2. Update `layer3/frontend/vercel.json` with your stats API URL
3. Deploy: `cd layer3/frontend && npx vercel --prod`

---

## Running Tests

```bash
cd honeypot
.venv/bin/pytest tests/ -v
```

34 tests covering SQLite schema, logger, session manager, rule-based cache, intent classifier, prompt builder, FastAPI endpoints, and stats API.
