import re

# Rule order matters: first match wins.
# High-specificity classes (credential_harvesting, web_recon, injection_attempt)
# are placed BEFORE data_exfiltration so that curl/wget commands targeting
# known attack paths are correctly categorised instead of defaulting to exfil.
_RULES: list[tuple[str, list[str]]] = [
    ("privilege_escalation", [
        r"\bsudo\b", r"\bsu\b",
        r"\bchmod\s+[0-7]*7[0-7]*\b",   # numeric SUID/world-writable modes
        r"\bchmod\b.*\+s",               # symbolic SUID: chmod u+s, g+s
        r"\bchmod\b.*\+x",               # make executable (attack prep)
        r"/etc/sudoers",
        r"-perm\s+-u=s", r"\bSUID\b",
        r"\bpasswd\s+\w",                # passwd <user> — password change
        r"\buseradd\b", r"\badduser\b",  # account creation
    ]),
    ("credential_harvesting", [          # before data_exfiltration (curl overlaps)
        r"wp-login\.php", r"phpmyadmin", r"pma_username", r"pma_password",
        r"log=.*pwd=",
    ]),
    ("web_recon", [                      # before data_exfiltration (curl overlaps)
        r"\.env\b", r"wp-config\.php", r"xmlrpc\.php",
        r"\.git/", r"admin/config",
    ]),
    ("injection_attempt", [              # before data_exfiltration (eval/base64 overlaps)
        r"union\s+select", r"<script",
        r"\bor\s+'?1'?='?1",             # OR 1=1 and OR '1'='1' variants
        r"1=1",
        r"\beval\b", r"base64_decode",
        r"onerror\s*=", r"onload\s*=",   # XSS event handlers
    ]),
    ("data_exfiltration", [
        r"\bcurl\b", r"\bwget\b", r"\bscp\b", r"\bnc\b",
        r"\bbase64\b", r"/etc/shadow",
        r"/dev/tcp",                     # covers >& /dev/tcp and > /dev/tcp
        r"\bpython\d?\b.*socket", r"\bpython\d?\b.*connect",  # python reverse shell
    ]),
    ("persistence", [
        r"\bcrontab\b", r"\.bashrc", r"authorized_keys",
        r"\bsystemctl\b.*enable", r"/etc/crontab",
        r"\bat\s", r"@reboot",           # `at` job scheduler; @reboot cron entry
    ]),
    ("lateral_movement", [
        r"\bssh\b\s+\S+@",              # ssh user@host
        r"\bssh\b\s+-",                  # ssh -i / -p / -L etc.
        r"\bnmap\b", r"\bping\b",
        r"/etc/hosts", r"\barp\b",
        r"\bapt(-get)?\b.*install", r"\byum\b.*install", r"\bpip\b.*install",
    ]),
    ("reconnaissance", [
        r"\bwhoami\b", r"\bid\b", r"\buname\b", r"\bls\b",
        r"\bcat\b", r"\bfind\b", r"\bgrep\b", r"\bps\b",
        r"\bnetstat\b", r"\bss\b", r"\bifconfig\b", r"\bip\s+addr\b",
        r"/etc/passwd", r"\bhostname\b",
        r"\benv\b", r"\bhistory\b",      # environment dump; command history
    ]),
]


def classify(command: str) -> tuple[str, float]:
    for intent, patterns in _RULES:
        for pattern in patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return intent, 0.95
    return "unknown", 0.3
