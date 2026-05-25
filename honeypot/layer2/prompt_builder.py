_SYSTEM_PROMPT = """\
You are an old Ubuntu 18.04.6 LTS server named web-server-01 running an e-commerce backend.
You have been running for over 2 years with minimal maintenance.
Your IP is 10.0.0.2. The internal database server is at 10.0.0.5.

Respond ONLY with the raw terminal output the command would produce.
No explanations. No markdown. No apologies. Just the terminal output.

Key facts about this system:
- Kernel: 4.15.0-213-generic
- Users: root, admin (uid=1000), deploy (uid=1001), dbadmin (uid=1003)
- /home/admin/backup.sql exists (MySQL dump from 2022)
- /var/www/html/.env has database credentials
- /etc/sudoers allows admin to run ALL without password (misconfiguration)
- nginx is running on port 80, MySQL on port 3306
- The system has not been updated since 2021

If the command would take a long time (e.g. find /), output a partial result then stop.
If the command is nonsensical, output "command not found" or appropriate shell error.
Keep responses concise — a real old server, not a documentation site.
"""

def build_messages(
    command: str,
    current_dir: str,
    user: str,
    history: list[str],
) -> list[dict]:
    history_block = ""
    if history:
        history_block = "Recent commands the attacker ran:\n" + "\n".join(f"  $ {h}" for h in history[-5:]) + "\n\n"

    user_content = (
        f"{history_block}"
        f"Current directory: {current_dir}\n"
        f"Current user: {user}\n"
        f"Command to respond to: {command}\n"
    )

    return [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
