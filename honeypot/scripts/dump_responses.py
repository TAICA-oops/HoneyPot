#!/usr/bin/env python3
"""
dump_responses.py — 從 honeypot.db 匯出所有 session 的指令與回應

Usage:
  cd HoneyPot/honeypot
  .venv/bin/python scripts/dump_responses.py              # 全部 session
  .venv/bin/python scripts/dump_responses.py --last 3     # 最近 3 個 session
  .venv/bin/python scripts/dump_responses.py --session <id>
  .venv/bin/python scripts/dump_responses.py --intent privilege_escalation
  .venv/bin/python scripts/dump_responses.py --llm-only   # 只看 LLM 生成（非 cache）
  .venv/bin/python scripts/dump_responses.py --out report.txt
"""
import argparse
import os
import sqlite3
import sys
from datetime import datetime

_R = "\033[0;31m"; _Y = "\033[1;33m"; _G = "\033[0;32m"
_B = "\033[0;34m"; _C = "\033[0;36m"; _W = "\033[1;37m"
_D = "\033[0m";    _BOLD = "\033[1m"

_INTENT_COLOUR = {
    "privilege_escalation": _R,
    "data_exfiltration":    _R,
    "credential_harvesting": _Y,
    "injection_attempt":    _Y,
    "persistence":          _Y,
    "lateral_movement":     _Y,
    "web_recon":            _C,
    "reconnaissance":       _C,
    "unknown":              _D,
}

_THREAT_COLOUR = {
    "Critical": _R, "High": _R, "Medium": _Y, "Low": _G,
}


def _db_path() -> str:
    from dotenv import load_dotenv
    load_dotenv()
    return os.getenv("DB_PATH", "./honeypot.db")


def _get_sessions(conn: sqlite3.Connection, session_id: str | None, last: int | None) -> list:
    if session_id:
        rows = conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchall()
    elif last:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (last,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM sessions ORDER BY start_time ASC"
        ).fetchall()
    return rows


def _get_commands(conn: sqlite3.Connection, session_id: str,
                  intent_filter: str | None, llm_only: bool) -> list:
    sql = "SELECT * FROM commands WHERE session_id=?"
    params: list = [session_id]
    if intent_filter:
        sql += " AND intent=?"
        params.append(intent_filter)
    if llm_only:
        sql += " AND cache_hit=0"
    sql += " ORDER BY timestamp ASC"
    return conn.execute(sql, params).fetchall()


def _fmt_response(resp: str, no_colour: bool) -> str:
    if not resp:
        return "  (no response)\n"
    lines = resp.rstrip("\n").split("\n")
    prefix = "  │ " if not no_colour else "  | "
    return "\n".join(prefix + l for l in lines) + "\n"


def dump(args, out):
    db = _db_path()
    if not os.path.exists(db):
        print(f"DB not found: {db}", file=sys.stderr)
        sys.exit(1)

    no_colour = (out is not sys.stdout) or args.no_colour
    C = lambda c, s: (s if no_colour else c + s + _D)

    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row

    sessions = _get_sessions(conn, args.session, args.last)
    if not sessions:
        print("No sessions found.", file=out)
        return

    total_cmds = 0
    for s in sessions:
        sid   = s["session_id"]
        proto = s["protocol"] or "?"
        ip    = s["attacker_ip"] or "?"
        start = s["start_time"] or ""
        threat = s["threat_level"] or "Unknown"
        tc = _THREAT_COLOUR.get(threat, _D)

        print(C(_BOLD, f"\n{'═'*70}"), file=out)
        print(C(_W, f"  Session  : {sid}"), file=out)
        print(f"  Protocol : {C(_C, proto)}   IP: {C(_C, ip)}", file=out)
        print(f"  Start    : {start}", file=out)
        print(f"  Threat   : {C(tc, threat)}", file=out)
        print(C(_BOLD, f"{'─'*70}"), file=out)

        cmds = _get_commands(conn, sid, args.intent, args.llm_only)
        if not cmds:
            print("  (no commands match filter)", file=out)
            continue

        for cmd in cmds:
            intent  = cmd["intent"] or "unknown"
            conf    = cmd["confidence"] or 0.0
            hit     = bool(cmd["cache_hit"])
            ic      = _INTENT_COLOUR.get(intent, _D)
            src     = C(_G, "cache") if hit else C(_Y, "LLM  ")
            tag     = C(ic, f"[{intent:<22}]")
            conf_s  = f"{conf:.2f}"
            command = cmd["command"] or ""

            print(f"\n  {src}  {tag}  conf={conf_s}", file=out)
            print(C(_W, f"  $ {command}"), file=out)
            print(_fmt_response(cmd["response"] or "", no_colour), file=out, end="")
            total_cmds += 1

    conn.close()
    print(C(_BOLD, f"\n{'═'*70}"), file=out)
    print(f"  Sessions: {len(sessions)}   Commands shown: {total_cmds}", file=out)


def main():
    ap = argparse.ArgumentParser(description="Dump honeypot DB responses for analysis")
    ap.add_argument("--session",   metavar="ID",      help="Filter by session ID")
    ap.add_argument("--last",      type=int, metavar="N", help="Show last N sessions")
    ap.add_argument("--intent",    metavar="INTENT",  help="Filter by intent category")
    ap.add_argument("--llm-only",  action="store_true", help="Show only LLM-generated responses (skip cache hits)")
    ap.add_argument("--no-colour", action="store_true", help="Disable ANSI colours")
    ap.add_argument("--out",       metavar="FILE",    help="Write output to file instead of stdout")
    args = ap.parse_args()

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            dump(args, f)
        print(f"Saved to {args.out}")
    else:
        dump(args, sys.stdout)


if __name__ == "__main__":
    main()
