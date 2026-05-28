from layer2.db import get_conn
from layer2.ollama_client import generate, get_report_model

_REPORT_SYSTEM = """\
You are a senior cybersecurity analyst writing a professional threat intelligence report.
Given attacker session logs from an SSH/HTTP honeypot, produce a Markdown report.

REQUIRED SECTIONS (in this order):

## Executive Summary
One paragraph: who attacked (IP), what protocol (SSH/HTTP), what they did, overall threat level.

## Attack Timeline
| Time | Command / Request | Intent | Notes |
|------|-------------------|--------|-------|
(one row per event, use actual timestamps from log)

## Intent Analysis
For each observed intent category, one bullet explaining what the attacker was doing and why it matters.

## MITRE ATT&CK Mapping
Map ONLY the behaviors actually observed to MITRE techniques. Format each as:
- **T[ID]** [Technique Name] — one sentence explaining the evidence

Common mappings to consider (only include if actually observed):
- T1078 Valid Accounts — used weak/default credentials
- T1059.004 Unix Shell — ran shell commands
- T1083 File and Directory Discovery — used ls, find
- T1003.008 /etc/passwd and /etc/shadow — accessed passwd or shadow
- T1552.001 Credentials In Files — accessed .env or wp-config.php
- T1548.003 Sudo and Sudo Caching — used sudo
- T1053.005 Scheduled Task/Job — modified crontab
- T1190 Exploit Public-Facing Application — scanned WordPress paths
- T1110.001 Password Guessing — attempted login with common passwords

## Indicators of Compromise (IoCs)
- **Attacker IP:** [IP address]
- **Tools/Downloads:** [any wget/curl targets, or "none observed"]
- **Credentials Attempted:** [usernames/passwords tried, or "none observed"]

## Threat Level Assessment
State one of: **Low** / **Medium** / **High** / **Critical**

Criteria:
- Critical = privilege_escalation AND data_exfiltration both present
- High = privilege_escalation OR data_exfiltration present
- Medium = persistence OR lateral_movement present
- Low = reconnaissance only

Justify with specific commands from the log.

RULES:
- Write in English
- Cite actual commands/paths from the log — do NOT invent details
- Keep each section concise but specific
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
    report = generate(messages, temperature=0.6, model=get_report_model())

    _FAILURE_STRINGS = ("bash: command timed out", "command not found")
    if any(report.strip().startswith(s) for s in _FAILURE_STRINGS):
        return "# Report Generation Failed\nOllama did not respond. Please try again later."

    conn = get_conn()
    conn.execute("UPDATE sessions SET report=? WHERE session_id=?", (report, session_id))
    conn.commit()
    conn.close()

    return report
