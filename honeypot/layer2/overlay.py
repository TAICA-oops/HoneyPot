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


def _descendants(path: str) -> list[str]:
    """覆寫層中位於 path 之下的所有子孫路徑(供 rm -r 一併刪除)。"""
    try:
        conn = get_conn()
        rows = conn.execute(
            "SELECT path FROM fs_overlay WHERE path LIKE ?", (path.rstrip("/") + "/%",)
        ).fetchall()
        conn.close()
        return [r[0] for r in rows]
    except sqlite3.Error:
        return []


def _children_rows(dir_path: str):
    """直接位於 dir_path 底下的覆寫列(以 LIKE 前綴查詢,再過濾直接子項)。"""
    d = dir_path.rstrip("/") or ""
    try:
        conn = get_conn()
        rows = conn.execute(
            "SELECT path, kind FROM fs_overlay WHERE path LIKE ?", (d + "/%",)
        ).fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    out = []
    for p, kind in rows:
        if _parent(p) == (d or "/"):
            out.append((p, kind))
    return out


# ── 讀取輔助（給 cache 用,皆為針對性查詢）─────────────────────────────────────
def lookup(path: str) -> tuple[str, str | None] | None:
    """回傳 (kind, content) 或 None(覆寫層無此路徑)。"""
    try:
        conn = get_conn()
        row = conn.execute(
            "SELECT kind, content FROM fs_overlay WHERE path=?", (path,)
        ).fetchone()
        conn.close()
        return (row[0], row[1]) if row else None
    except sqlite3.Error:
        return None


def read_file(path: str) -> str | None:
    row = lookup(path)
    return row[1] if row and row[0] == "file" else None


def is_deleted(path: str) -> bool:
    row = lookup(path)
    return bool(row) and row[0] == "deleted"


def is_dir(path: str) -> bool:
    row = lookup(path)
    return bool(row) and row[0] == "dir"


def list_extra(dir_path: str) -> list[str]:
    """覆寫層中直接位於 dir_path 底下、未被刪除的項目名稱。"""
    return [p.rstrip("/").rsplit("/", 1)[-1]
            for p, kind in _children_rows(dir_path) if kind != "deleted"]


def deleted_names(dir_path: str) -> set[str]:
    return {p.rstrip("/").rsplit("/", 1)[-1]
            for p, kind in _children_rows(dir_path) if kind == "deleted"}


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


def _mkdirs(path: str, parents: bool) -> None:
    """建立目錄;parents=True 時連同所有上層目錄一起建立(mkdir -p)。"""
    if parents:
        parts = path.strip("/").split("/")
        acc = ""
        for seg in parts:
            acc = acc + "/" + seg
            if not is_dir(acc):
                _set(acc, "dir")
    else:
        _set(path, "dir")


def _apply_write(command: str, current_dir: str, user: str) -> str | None:
    cmd = _unwrap(command)
    # 經 sudo 提權者以 root 身分執行寫入(NOPASSWD),否則以原使用者身分
    wuser = "root" if command.strip().startswith("sudo ") else user

    # rm [-rf] PATH...
    m = re.match(r"^rm\b(.*)$", cmd)
    if m:
        toks = _tokens(m.group(1))
        flags = "".join(f[1:] for f in toks if f.startswith("-"))
        recursive, force = ("r" in flags or "R" in flags), ("f" in flags)
        targets = [t for t in toks if not t.startswith("-")]
        if any(t in ("/", "/*") for t in targets):
            return _RM_FAILSAFE
        if not targets:
            return None
        for t in targets:
            path = _norm(current_dir, t)
            if not fake_fs.can_write(path, wuser):
                return f"rm: cannot remove '{t}': Permission denied\n"
            existing_dir = is_dir(path) or path in fake_fs.FAKE_DIRS
            existing_file = (read_file(path) is not None) or path in fake_fs.FAKE_FILES
            if existing_dir and not recursive:
                return f"rm: cannot remove '{t}': Is a directory\n"
            if not existing_dir and not existing_file and not force:
                return f"rm: cannot remove '{t}': No such file or directory\n"
            _set(path, "deleted")
            if recursive:                                  # 連同子項一併標記刪除
                for p in _descendants(path):
                    _set(p, "deleted")
        return ""

    # mkdir [-p] DIR...
    m = re.match(r"^mkdir\b(.*)$", cmd)
    if m:
        toks = _tokens(m.group(1))
        parents = any(f.startswith("-") and "p" in f for f in toks)
        dirs = [t for t in toks if not t.startswith("-")]
        if not dirs:
            return None
        for d in dirs:
            path = _norm(current_dir, d)
            if not fake_fs.can_write(path, wuser):
                return f"mkdir: cannot create directory '{d}': Permission denied\n"
            _mkdirs(path, parents)
        return ""

    # touch FILE...
    m = re.match(r"^touch\b(.*)$", cmd)
    if m:
        files = [t for t in _tokens(m.group(1)) if not t.startswith("-")]
        if not files:
            return None
        for f in files:
            path = _norm(current_dir, f)
            if not fake_fs.can_write(path, wuser):
                return f"touch: cannot touch '{f}': Permission denied\n"
            if read_file(path) is None and not is_dir(path):
                _set(path, "file", "")
        return ""

    # useradd / adduser（需 root）
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
        if wuser != "root":
            return ("useradd: Permission denied.\n"
                    "useradd: cannot lock /etc/passwd; try again later.\n")
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
            if not fake_fs.can_write(path, wuser):
                return f"bash: {toks[i + 1]}: Permission denied\n"
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
