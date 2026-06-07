"""可變狀態覆寫層 (mutable-state overlay)。

攻擊者造成的變更（建立/修改/刪除檔案、mkdir、useradd、寫入 /etc/passwd 等）
寫進共用的 SQLite `fs_overlay` 表,讓之後的讀取——不論同一連線、重新連線、或
跨程序（Layer1 SSH ↔ Layer2 引擎）——都反映這些變更,消除「改了卻讀不到」的破綻。

讀取一律防禦性處理：DB／資料表不存在時回傳「沒有覆寫」而非讓蜜罐崩潰。
"""
import re
import shlex
import sqlite3
from layer2.db import get_conn
from shared import fake_fs

_RM_FAILSAFE = (
    "rm: it is dangerous to operate recursively on '/'\n"
    "rm: use --no-preserve-root to override this failsafe\n"
)


# ── 低階存取 ────────────────────────────────────────────────────────────────
def _norm(current_dir: str, path: str) -> str:
    return fake_fs.normalize_path(current_dir, path.strip().strip('"').strip("'"))


def _parent(path: str) -> str:
    p = path.rstrip("/")
    return p.rsplit("/", 1)[0] or "/"


_MAX_ROWS = 1000   # 上限,避免攻擊者狂建檔把覆寫層撐爆


def _set(path: str, kind: str, content: str | None = None) -> None:
    try:
        conn = get_conn()
        conn.execute(
            "INSERT INTO fs_overlay (path, kind, content, updated) VALUES (?,?,?,CURRENT_TIMESTAMP) "
            "ON CONFLICT(path) DO UPDATE SET kind=excluded.kind, content=excluded.content, "
            "updated=CURRENT_TIMESTAMP",
            (path, kind, content),
        )
        # 超過上限時逐出最舊的（保留最近的變更）
        conn.execute(
            "DELETE FROM fs_overlay WHERE path IN ("
            "  SELECT path FROM fs_overlay ORDER BY updated DESC, rowid DESC LIMIT -1 OFFSET ?)",
            (_MAX_ROWS,),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        pass


def _rows():
    try:
        conn = get_conn()
        rows = conn.execute("SELECT path, kind, content FROM fs_overlay").fetchall()
        conn.close()
        return [(r[0], r[1], r[2]) for r in rows]
    except sqlite3.Error:
        return []


# ── 讀取輔助（給 cache 用）──────────────────────────────────────────────────
def read_file(path: str) -> str | None:
    for p, kind, content in _rows():
        if p == path:
            return content if kind == "file" else None
    return None


def is_deleted(path: str) -> bool:
    return any(p == path and kind == "deleted" for p, kind, _ in _rows())


def is_dir(path: str) -> bool:
    return any(p == path and kind == "dir" for p, kind, _ in _rows())


def list_extra(dir_path: str) -> list[str]:
    """覆寫層中直接位於 dir_path 底下、未被刪除的項目名稱。"""
    names = []
    for p, kind, _ in _rows():
        if kind == "deleted":
            continue
        if _parent(p) == dir_path.rstrip("/") or _parent(p) == (dir_path or "/"):
            names.append(p.rstrip("/").rsplit("/", 1)[-1])
    return names


def deleted_names(dir_path: str) -> set[str]:
    out = set()
    for p, kind, _ in _rows():
        if kind == "deleted" and _parent(p) == (dir_path.rstrip("/") or "/"):
            out.add(p.rstrip("/").rsplit("/", 1)[-1])
    return out


# ── 寫入偵測 ────────────────────────────────────────────────────────────────
def _unwrap(cmd: str) -> str:
    c = cmd.strip()
    if c.startswith("sudo "):
        c = c[5:].strip()
        # 跳過常見 sudo 旗標
        c = re.sub(r"^(-[A-Za-z]+\s+|-u\s+\S+\s+)+", "", c)
    m = re.match(r"""^(?:bash|sh|/bin/bash|/bin/sh)\s+-c\s+(['"])(.*)\1\s*$""", c)
    if m:
        c = m.group(2).strip()
    return c


def _tokens(s: str) -> list[str]:
    try:
        return shlex.split(s, posix=True)
    except ValueError:
        return s.split()


def _echo_content(left_tokens: list[str]) -> str:
    args, newline = left_tokens[1:], True
    parts = []
    for a in args:
        if a == "-n":
            newline = False
        elif a == "-e":
            continue
        else:
            parts.append(a)
    return " ".join(parts) + ("\n" if newline else "")


def _current_passwd() -> str:
    return read_file("/etc/passwd") or fake_fs.ETC_PASSWD


def _next_uid() -> int:
    uids = [n for n in fake_fs.UID_MAP.values()]
    for line in _current_passwd().splitlines():
        parts = line.split(":")
        if len(parts) > 2 and parts[2].isdigit():
            uids.append(int(parts[2]))
    return max([u for u in uids if u < 60000] + [1004]) + 1


def apply_write(command: str, current_dir: str, user: str) -> str | None:
    """若 command 是寫入類指令則更新覆寫層並回傳輸出;否則回 None（交給 cache/LLM）。"""
    try:
        return _apply_write(command, current_dir, user)
    except Exception:
        return None


def _apply_write(command: str, current_dir: str, user: str) -> str | None:
    cmd = _unwrap(command)

    # rm
    m = re.match(r"^rm\b(.*)$", cmd)
    if m:
        toks = _tokens(m.group(1))
        targets = [t for t in toks if not t.startswith("-")]
        if any(t in ("/", "/*") for t in targets):
            return _RM_FAILSAFE
        if not targets:
            return None
        for t in targets:
            _set(_norm(current_dir, t), "deleted")
        return ""

    # mkdir [-p] DIR...
    m = re.match(r"^mkdir\b(.*)$", cmd)
    if m:
        toks = _tokens(m.group(1))
        dirs = [t for t in toks if not t.startswith("-")]
        if not dirs:
            return None
        for d in dirs:
            _set(_norm(current_dir, d), "dir")
        return ""

    # touch FILE...
    m = re.match(r"^touch\b(.*)$", cmd)
    if m:
        files = [t for t in _tokens(m.group(1)) if not t.startswith("-")]
        if not files:
            return None
        for f in files:
            path = _norm(current_dir, f)
            if read_file(path) is None and not is_dir(path):
                _set(path, "file", "")
        return ""

    # useradd / adduser
    m = re.match(r"^(?:useradd|adduser)\b(.*)$", cmd)
    if m:
        toks = _tokens(m.group(1))
        uid, make_home, shell, name = None, False, "/bin/bash", None
        i = 0
        while i < len(toks):
            t = toks[i]
            if t == "-u" and i + 1 < len(toks):
                uid = int(toks[i + 1]) if toks[i + 1].isdigit() else None
                i += 2
                continue
            if t in ("-m", "--create-home"):
                make_home = True
            elif t == "-s" and i + 1 < len(toks):
                shell = toks[i + 1]
                i += 2
                continue
            elif not t.startswith("-"):
                name = t
            i += 1
        if not name:
            return None
        uid = uid or _next_uid()
        line = f"{name}:x:{uid}:{uid}::/home/{name}:{shell}"
        cur = _current_passwd()
        if not cur.endswith("\n"):
            cur += "\n"
        _set("/etc/passwd", "file", cur + line + "\n")
        if make_home:
            _set(f"/home/{name}", "dir")
        return ""

    # 含 shell 運算子的複合指令交給 LLM(避免只處理重導向、吃掉 && / | / ; 後半段)
    if re.search(r"&&|\|\||;|\s\|\s", cmd):
        return None

    # 重導向寫入：echo ... > / >> PATH（含被 sudo bash -c 包住的情況）
    toks = _tokens(cmd)
    for i, t in enumerate(toks):
        if t in (">", ">>") and i + 1 < len(toks):
            path = _norm(current_dir, toks[i + 1])
            if path.startswith("/dev/"):
                return None      # 丟棄輸出(/dev/null 等)→ 交給 LLM,不建檔
            left = toks[:i]
            content = _echo_content(left) if left and left[0] == "echo" else ""
            if t == ">>":
                base = read_file(path)
                if base is None and path == "/etc/passwd":
                    base = fake_fs.ETC_PASSWD
                content = (base or "") + content
            _set(path, "file", content)
            return ""

    return None
