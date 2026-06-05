FAKE_DIRS = {
    "/", "/etc", "/home",
    "/home/admin", "/home/deploy", "/home/backup", "/home/dbadmin",
    "/var", "/var/www", "/var/www/html", "/tmp",
    "/proc", "/usr", "/usr/bin", "/opt",
}

class SessionManager:
    def __init__(self):
        self._sessions: dict[str, dict] = {}

    def create(self, session_id: str, user: str, ip: str) -> dict:
        self._sessions[session_id] = {
            "current_dir": "/home/admin",
            "user": user,
            "ip": ip,
            "history": [],          # list[str]，舊的，保留向後相容
            "history_pairs": [],    # list[tuple[str, str]]，指令+回應配對
        }
        return self._sessions[session_id]

    def get(self, session_id: str) -> dict:
        return self._sessions[session_id]

    def push_history(self, session_id: str, command: str) -> None:
        h = self._sessions[session_id]["history"]
        h.append(command)
        if len(h) > 10:
            self._sessions[session_id]["history"] = h[-10:]

    def push_history_with_response(self, session_id: str, command: str, response: str) -> None:
        h = self._sessions[session_id]["history_pairs"]
        h.append((command, response[:500]))
        if len(h) > 20:
            self._sessions[session_id]["history_pairs"] = h[-20:]
        self.push_history(session_id, command)

    def handle_cd(self, session_id: str, command: str) -> tuple[str, str]:
        parts = command.split(maxsplit=1)
        current = self._sessions[session_id]["current_dir"]

        if len(parts) == 1 or parts[1] == "~":
            target = "/home/admin"
        elif parts[1] == "..":
            target = "/".join(current.rstrip("/").split("/")[:-1]) or "/"
        elif parts[1].startswith("/"):
            target = parts[1].rstrip("/") or "/"
        else:
            target = (current.rstrip("/") + "/" + parts[1])

        if target in FAKE_DIRS:
            self._sessions[session_id]["current_dir"] = target
            return target, ""
        return current, f"bash: cd: {parts[1] if len(parts) > 1 else ''}: No such file or directory\n"

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
