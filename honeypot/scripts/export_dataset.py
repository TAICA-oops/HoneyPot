#!/usr/bin/env python3
"""
Dataset Export Script
把 honeypot.db 的攻擊日誌匯出成 CSV + JSON，供評估和分析使用。

Usage:
    cd HoneyPot/honeypot
    .venv/bin/python scripts/export_dataset.py [--output-dir OUTPUT]
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from layer2.db import get_conn


def export(db_path: str | None, output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    conn = get_conn(db_path)
    conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))

    # ── 1. Sessions ─────────────────────────────────────────────────────────
    sessions = conn.execute("""
        SELECT session_id, protocol, attacker_ip, threat_level,
               start_time, end_time
        FROM sessions
        ORDER BY start_time
    """).fetchall()

    sessions_path = os.path.join(output_dir, "sessions.csv")
    if sessions:
        with open(sessions_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(sessions[0].keys()))
            writer.writeheader()
            writer.writerows(sessions)
        print(f"[sessions]  {len(sessions):>6} rows → {sessions_path}")
    else:
        print("[sessions]  0 rows (no data yet)")

    # ── 2. Commands ─────────────────────────────────────────────────────────
    commands = conn.execute("""
        SELECT c.id, c.session_id, s.protocol, s.attacker_ip,
               c.command, c.response, c.intent, c.confidence,
               c.cache_hit, c.timestamp
        FROM commands c
        JOIN sessions s ON c.session_id = s.session_id
        ORDER BY c.timestamp
    """).fetchall()

    commands_path = os.path.join(output_dir, "commands.csv")
    if commands:
        with open(commands_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(commands[0].keys()))
            writer.writeheader()
            writer.writerows(commands)
        print(f"[commands]  {len(commands):>6} rows → {commands_path}")
    else:
        print("[commands]  0 rows (no data yet)")

    # ── 3. Intent stats ──────────────────────────────────────────────────────
    intent_stats = conn.execute("""
        SELECT intent,
               COUNT(*) AS count,
               ROUND(AVG(confidence), 3) AS avg_confidence,
               ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM commands), 1) AS pct
        FROM commands
        GROUP BY intent
        ORDER BY count DESC
    """).fetchall()

    stats_path = os.path.join(output_dir, "intent_stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(intent_stats, f, indent=2, ensure_ascii=False)
    print(f"[intent stats] {len(intent_stats)} categories → {stats_path}")

    # ── 4. Threat level distribution ─────────────────────────────────────────
    threat_dist = conn.execute("""
        SELECT threat_level, COUNT(*) AS sessions, protocol
        FROM sessions
        GROUP BY threat_level, protocol
        ORDER BY sessions DESC
    """).fetchall()

    # ── 5. Summary JSON ──────────────────────────────────────────────────────
    summary = {
        "exported_at": datetime.now().isoformat(),
        "db_path": db_path or os.environ.get("DB_PATH", "honeypot.db"),
        "totals": {
            "sessions": len(sessions),
            "commands": len(commands),
            "unique_ips": len({s["attacker_ip"] for s in sessions}),
        },
        "threat_levels": threat_dist,
        "intent_distribution": intent_stats,
        "cache_hit_rate": (
            round(sum(1 for c in commands if c["cache_hit"]) / len(commands), 3)
            if commands else 0
        ),
        "protocols": {
            p: sum(1 for s in sessions if s["protocol"] == p)
            for p in ("ssh", "http")
        },
    }

    summary_path = os.path.join(output_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"[summary]      → {summary_path}")

    conn.close()

    # ── print summary ────────────────────────────────────────────────────────
    print()
    print("Dataset Summary")
    print("=" * 40)
    print(f"  Sessions  : {summary['totals']['sessions']}")
    print(f"  Commands  : {summary['totals']['commands']}")
    print(f"  Unique IPs: {summary['totals']['unique_ips']}")
    print(f"  Cache hit : {summary['cache_hit_rate']:.1%}")
    print(f"  SSH / HTTP: {summary['protocols'].get('ssh', 0)} / {summary['protocols'].get('http', 0)}")
    if intent_stats:
        print()
        print("  Intent breakdown:")
        for row in intent_stats:
            bar = "█" * int(row["pct"] / 2)
            print(f"    {row['intent']:<25} {row['count']:>5}  ({row['pct']:>5.1f}%)  {bar}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export honeypot dataset")
    parser.add_argument("--db", default=None, help="Path to honeypot.db (default: from .env)")
    parser.add_argument("--output-dir", default="dataset", help="Output directory (default: dataset/)")
    args = parser.parse_args()

    export(args.db, args.output_dir)
