from shared import fake_fs

# 目錄集合改由 shared.fake_fs 提供（與 ls 列出的內容同源，避免「看得到卻 cd 不進去」）
FAKE_DIRS = fake_fs.FAKE_DIRS

_SHELL_BINS = {"bash", "sh", "zsh", "/bin/bash", "/bin/sh", "/bin/zsh"}


def _overlay_is_dir(path: str) -> bool:
    """攻擊者用 mkdir 建立的目錄（存在共用 SQLite 覆寫層）也應可 cd 進去。
    防禦性：覆寫層／DB 不可用時回 False,絕不讓 cd 崩潰。"""
    try:
        from layer2 import overlay
        return overlay.is_dir(path)
    except Exception:
        return False


def detect_escalation(command: str) -> str | None:
    """判斷指令是否會開啟「持續的」提權 shell。

    回傳目標使用者（通常是 root），否則回傳 None。
    帶 -c 的單次執行 (sudo bash -c '...') 不算持續提權,維持原身分。
    """
    toks = command.strip().split()
    if not toks or toks[0] != "sudo":
        return None
    rest = toks[1:]
    if not rest or "-c" in rest:
        return None
    if rest[0] in ("-i", "--login", "-s"):
        return "root"
    if rest[0] == "su":
        targets = [a for a in rest[1:] if a not in ("-", "-l", "--login")]
        return targets[0] if targets else "root"
    if rest[0] in _SHELL_BINS:
        return "root"
    return None


class SessionManager:
    def __init__(self):
        self._sessions: dict[str, dict] = {}

    def create(self, session_id: str, user: str, ip: str) -> dict:
        self._sessions[session_id] = {
            "current_dir": fake_fs.home_for(user),   # 登入落在該使用者家目錄
            "user": user,                            # 登入帳號（不變）
            "ip": ip,
            "history": [],          # list[str]，舊的，保留向後相容
            "history_pairs": [],    # list[tuple[str, str]]，指令+回應配對
            # 提權堆疊：每層記錄該 shell 的身分與退出時要還原的工作目錄
            "user_stack": [{"user": user, "return_dir": fake_fs.home_for(user)}],
        }
        return self._sessions[session_id]

    def get(self, session_id: str) -> dict:
        return self._sessions[session_id]

    def effective_user(self, session_id: str) -> str:
        """目前實際生效的身分（提權後為 root）。"""
        return self._sessions[session_id]["user_stack"][-1]["user"]

    def push_user(self, session_id: str, new_user: str, login_shell: bool = False) -> None:
        s = self._sessions[session_id]
        s["user_stack"].append({"user": new_user, "return_dir": s["current_dir"]})
        if login_shell:   # sudo -i / su -  → 切到新身分的家目錄
            s["current_dir"] = fake_fs.home_for(new_user)

    def pop_user(self, session_id: str) -> bool:
        """退出一層提權 shell。已在最底層（登入 shell）回 False → 呼叫端結束 session。"""
        s = self._sessions[session_id]
        if len(s["user_stack"]) <= 1:
            return False
        frame = s["user_stack"].pop()
        s["current_dir"] = frame["return_dir"]
        return True

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

    def seed_history(self, session_id: str, pairs: list[tuple[str, str]]) -> None:
        """以先前(跨連線)的指令+回應預先填充本 session 歷史,讓 LLM 有脈絡延續性。"""
        s = self._sessions[session_id]
        for command, response in pairs[-20:]:
            s["history_pairs"].append((command, (response or "")[:500]))
            s["history"].append(command)
        s["history_pairs"] = s["history_pairs"][-20:]
        s["history"] = s["history"][-10:]

    def handle_cd(self, session_id: str, command: str) -> tuple[str, str]:
        parts = command.split(maxsplit=1)
        current = self._sessions[session_id]["current_dir"]
        user = self.effective_user(session_id)

        if len(parts) == 1 or parts[1] == "~":
            target = fake_fs.home_for(user)
        else:
            target = fake_fs.normalize_path(current, parts[1])

        if target in FAKE_DIRS or _overlay_is_dir(target):
            self._sessions[session_id]["current_dir"] = target
            return target, ""
        if target in fake_fs.FAKE_FILES:
            return current, f"bash: cd: {parts[1]}: Not a directory\n"
        return current, f"bash: cd: {parts[1] if len(parts) > 1 else ''}: No such file or directory\n"

    def delete(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
