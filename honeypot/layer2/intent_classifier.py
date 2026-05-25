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
