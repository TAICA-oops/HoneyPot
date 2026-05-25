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
