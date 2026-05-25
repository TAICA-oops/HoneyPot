FAKE_DIRS = {
    "/", "/etc", "/home", "/home/admin", "/home/deploy",
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
            "history": [],
        }
        return self._sessions[session_id]

    def get(self, session_id: str) -> dict:
        return self._sessions[session_id]

    def push_history(self, session_id: str, command: str) -> None:
        h = self._sessions[session_id]["history"]
        h.append(command)
        if len(h) > 10:
            self._sessions[session_id]["history"] = h[-10:]

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
