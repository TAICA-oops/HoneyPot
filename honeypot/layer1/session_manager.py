from shared import fake_fs

# 目錄集合改由 shared.fake_fs 提供（與 ls 列出的內容同源，避免「看得到卻 cd 不進去」）
FAKE_DIRS = fake_fs.FAKE_DIRS

class SessionManager:
    def __init__(self):
        self._sessions: dict[str, dict] = {}

    def create(self, session_id: str, user: str, ip: str) -> dict:
        self._sessions[session_id] = {
            "current_dir": fake_fs.home_for(user),   # 登入落在該使用者家目錄
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
        user = self._sessions[session_id]["user"]

        if len(parts) == 1 or parts[1] == "~":
            target = fake_fs.home_for(user)
        else:
            target = fake_fs.normalize_path(current, parts[1])

        if target in FAKE_DIRS:
            self._sessions[session_id]["current_dir"] = target
            return target, ""
        if target in fake_fs.FAKE_FILES:
            return current, f"bash: cd: {parts[1]}: Not a directory\n"
        return current, f"bash: cd: {parts[1] if len(parts) > 1 else ''}: No such file or directory\n"

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
