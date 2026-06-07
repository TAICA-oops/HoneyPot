import os
import socket
import threading
import time
import uuid
import paramiko
from dotenv import load_dotenv
from layer1.session_manager import SessionManager, detect_escalation
from layer1 import llm_client
from layer1.logger import Logger
from shared import fake_fs

load_dotenv()

HOST_KEY_PATH = ".ssh_host_key"


def _format_prompt(user: str, current_dir: str) -> str:
    """擬真 bash PS1：家目錄收合成 ~,root 用 # 提示符。"""
    home = fake_fs.home_for(user)
    if current_dir == home:
        disp = "~"
    elif current_dir.startswith(home + "/"):
        disp = "~" + current_dir[len(home):]
    else:
        disp = current_dir
    char = "#" if user == "root" else "$"
    return f"{user}@web-server-01:{disp}{char} "

_VALID_CREDS: dict[str, list[str]] = {
    "admin":   ["admin", "password", "123456", "admin123", "Admin@123"],
    "root":    ["toor", "root", "password", "123456", "P@ssw0rd"],
    "deploy":  ["deploy", "deploy123", "d3ploy"],
    "ubuntu":  ["ubuntu", "ubuntu123"],
    "dbadmin": ["Sup3rS3cr3t!2019", "dbadmin"],
}

_ECDSA_KEY_PATH = ".ssh_host_ecdsa_key"
_ED25519_KEY_PATH = ".ssh_host_ed25519_key"

# OpenSSH 7.6p1 (Ubuntu 18.04) 預設提供的演算法順序;與 paramiko 支援的取交集後套用,
# 把 paramiko 多出來的老演算法 (3des-cbc / group1-sha1 / hmac-md5 / ssh-dss) 拿掉,
# 讓 KEX/cipher/MAC 協商指紋更貼近真實 OpenSSH,降低被蜜罐偵測工具一眼識破。
_OPENSSH_KEX = [
    "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512", "diffie-hellman-group14-sha256",
    "diffie-hellman-group14-sha1",
]
_OPENSSH_CIPHERS = ["aes128-ctr", "aes192-ctr", "aes256-ctr"]
_OPENSSH_MACS = [
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
]
_OPENSSH_KEYS = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]


def _prefer(available, wanted: list) -> list:
    """回傳 wanted ∩ available（保留 wanted 的順序）;無交集時退回 available 以免連線失敗。"""
    kept = [a for a in wanted if a in available]
    return kept or list(available)


def _harden_transport(transport: paramiko.Transport) -> None:
    try:
        opts = transport.get_security_options()
        opts.kex = _prefer(opts.kex, _OPENSSH_KEX)
        opts.ciphers = _prefer(opts.ciphers, _OPENSSH_CIPHERS)
        opts.digests = _prefer(opts.digests, _OPENSSH_MACS)
        opts.key_types = _prefer(opts.key_types, _OPENSSH_KEYS)
    except Exception as e:
        print(f"[ssh] could not harden algorithms: {e}")


def _ed25519_key():
    """用 cryptography 產生 Ed25519 host key（paramiko 3.x 無 Ed25519Key.generate）。"""
    if os.path.exists(_ED25519_KEY_PATH):
        return paramiko.Ed25519Key(filename=_ED25519_KEY_PATH)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    with open(_ED25519_KEY_PATH, "wb") as f:
        f.write(pem)
    os.chmod(_ED25519_KEY_PATH, 0o600)
    return paramiko.Ed25519Key(filename=_ED25519_KEY_PATH)


def _host_keys() -> list:
    """提供 RSA + ECDSA + Ed25519 三型別 host key,與真實 Ubuntu sshd 一致。"""
    keys = []
    if os.path.exists(HOST_KEY_PATH):
        keys.append(paramiko.RSAKey(filename=HOST_KEY_PATH))
    else:
        k = paramiko.RSAKey.generate(2048)
        k.write_private_key_file(HOST_KEY_PATH)
        keys.append(k)
    try:
        if os.path.exists(_ECDSA_KEY_PATH):
            keys.append(paramiko.ECDSAKey(filename=_ECDSA_KEY_PATH))
        else:
            k = paramiko.ECDSAKey.generate()
            k.write_private_key_file(_ECDSA_KEY_PATH)
            keys.append(k)
    except Exception as e:
        print(f"[ssh] ECDSA host key unavailable: {e}")
    try:
        keys.append(_ed25519_key())
    except Exception as e:
        print(f"[ssh] Ed25519 host key unavailable: {e}")
    return keys

_SESSION_MGR = SessionManager()
_HOST_KEYS = _host_keys()

class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, addr_ip: str):
        self.username = "admin"
        self.addr_ip = addr_ip
        self._shell_ready = threading.Event()
        self.exec_command: str | None = None   # 非互動式 `ssh host 'cmd'` 的指令

    def check_auth_password(self, username, password):
        allowed = _VALID_CREDS.get(username, [])
        if password in allowed:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self._shell_ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        # 支援 `ssh user@host 'cmd'`（攻擊工具常用）；記錄指令並放行,由主執行緒處理
        self.exec_command = command.decode() if isinstance(command, bytes) else command
        self._shell_ready.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_banner(self):
        return ("Ubuntu 18.04.6 LTS", "en-US")


def _compute_threat_level(session_id: str) -> str:
    from layer2.db import get_conn
    conn = get_conn()
    rows = conn.execute(
        "SELECT intent FROM commands WHERE session_id=?", (session_id,)
    ).fetchall()
    conn.close()
    intents = set(r[0] for r in rows)
    if "privilege_escalation" in intents and "data_exfiltration" in intents:
        return "Critical"
    if "privilege_escalation" in intents or "data_exfiltration" in intents:
        return "High"
    if "persistence" in intents or "lateral_movement" in intents:
        return "Medium"
    return "Low"


def _auto_generate_report(session_id: str) -> None:
    # 排入單一 worker 佇列串行生成,避免大量 session 同時結束時併發灌爆 Ollama
    try:
        from layer3.report_generator import enqueue_report
        enqueue_report(session_id)
    except Exception as e:
        print(f"[ssh] could not enqueue report: {e}")


def _handle_exec(chan, session_id: str, command: str, logger: Logger, attacker_ip: str = "") -> None:
    """處理非互動式 `ssh user@host 'cmd'`：跑單一指令、回輸出、設退出碼。"""
    command = (command or "").strip()
    try:
        if not command or command in ("exit", "quit", "logout"):
            chan.send_exit_status(0)
            return
        eff_user = _SESSION_MGR.effective_user(session_id)
        if command == "cd" or command.startswith("cd "):
            _, err = _SESSION_MGR.handle_cd(session_id, command)
            output, intent, conf, cache_hit = err, "reconnaissance", 0.9, True
        else:
            result = llm_client.respond(
                session_id=session_id, protocol="ssh", command=command,
                current_dir=_SESSION_MGR.get(session_id)["current_dir"],
                user=eff_user, history=[], attacker_ip=attacker_ip,
            )
            output = result["response"]
            intent, conf, cache_hit = result["intent"], result["confidence"], result["cache_hit"]
        if output and not output.endswith("\n"):
            output += "\n"
        logger.command(session_id, command, output, intent, conf, cache_hit)
        for c in output:
            chan.send(b"\r\n" if c == "\n" else c.encode())
    except Exception as e:
        print(f"[ssh] exec error: {e}")
    finally:
        try:
            chan.send_exit_status(0)
        except Exception:
            pass


def _handle_client(sock: socket.socket, addr: tuple, logger: Logger) -> None:
    transport = None
    session_id = None
    _session_ended = False

    def _end_session():
        nonlocal _session_ended
        if session_id and not _session_ended:
            _session_ended = True
            try:
                level = _compute_threat_level(session_id)
                logger.session_end(session_id, level)
                _auto_generate_report(session_id)
            except Exception as e:
                print(f"[ssh] session cleanup error: {e}")
        if session_id:
            _SESSION_MGR.delete(session_id)

    try:
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"
        for _k in _HOST_KEYS:
            transport.add_server_key(_k)
        _harden_transport(transport)   # 協商演算法對齊 OpenSSH 7.6
        server = _ServerInterface(addr[0])
        transport.start_server(server=server)

        chan = transport.accept(30)
        if chan is None:
            return
        server._shell_ready.wait(10)

        session_id = str(uuid.uuid4())
        _SESSION_MGR.create(session_id, server.username, addr[0])
        logger.session_start(session_id, "ssh", addr[0])

        # 跨連線記憶：同一 IP 重連時,用先前的指令脈絡預載,讓蜜罐「記得」攻擊者
        try:
            prior = logger.recent_pairs_for_ip(addr[0], limit=15, exclude_session=session_id)
            if prior:
                _SESSION_MGR.seed_history(session_id, prior)
        except Exception as e:
            print(f"[ssh] could not seed history: {e}")

        # 非互動式 `ssh user@host 'cmd'`：執行單一指令、回傳輸出、設定退出碼後結束
        if server.exec_command is not None:
            _handle_exec(chan, session_id, server.exec_command, logger, addr[0])
            _end_session()
            return

        chan.send(
            b"\r\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)\r\n"
            b" * Documentation:  https://help.ubuntu.com\r\n\r\n"
        )

        buf = ""
        timeout = int(os.getenv("SESSION_TIMEOUT_SECONDS", "600"))
        chan.settimeout(timeout)

        while True:
            session = _SESSION_MGR.get(session_id)
            eff_user = _SESSION_MGR.effective_user(session_id)
            prompt = _format_prompt(eff_user, session['current_dir'])
            chan.send(prompt.encode())

            esc_active = False   # 是否正在吞 ANSI 跳脫序列(方向鍵/功能鍵)
            while True:
                try:
                    data = chan.recv(256)
                except Exception:
                    # timeout 或連線中斷：先記錄 session 結束再 return
                    _end_session()
                    return
                if not data:
                    _end_session()
                    return
                text = data.decode("utf-8", errors="replace")

                # Process character by character so that bulk sends (e.g. from
                # attack scripts that send "cmd\n" in one chunk) are handled
                # correctly alongside interactive one-char-at-a-time input.
                done = False
                for ch in text:
                    if esc_active:
                        # ANSI 跳脫序列(如方向鍵 \x1b[A):吞掉直到結尾位元組
                        if ch in "[O;" or ch.isdigit():
                            continue
                        esc_active = False
                        if "\x40" <= ch <= "\x7e":
                            continue   # 結尾位元組(字母等),整段丟棄
                        # 否則(殘留的控制字元)落下去照常處理
                    if ch == "\x1b":      # ESC：方向鍵/功能鍵序列開頭
                        esc_active = True
                        continue
                    if ch == "\t":        # Tab：無自動補全,直接吞掉避免亂碼
                        continue
                    if ch in ("\r", "\n"):
                        chan.send(b"\r\n")
                        done = True
                        break
                    elif ch in ("\x7f", "\x08"):
                        if buf:
                            buf = buf[:-1]
                            chan.send(b"\x08 \x08")
                    elif ch == "\x03":
                        buf = ""
                        chan.send(b"^C\r\n")
                        done = True
                        break
                    elif ch == "\x04":
                        # Ctrl-D：在提權 shell 中先退回上一層,最底層才結束連線
                        if _SESSION_MGR.pop_user(session_id):
                            chan.send(b"exit\r\n")
                            done = True
                            break
                        chan.send(b"logout\r\n")
                        _end_session()
                        return
                    else:
                        buf += ch
                        chan.send(ch.encode())
                if done:
                    break

            command = buf.strip()
            buf = ""

            if not command:
                continue

            if command in ("exit", "quit", "logout"):
                # 在提權 shell 中 exit 只退回上一層,最底層才登出
                if _SESSION_MGR.pop_user(session_id):
                    chan.send(b"exit\r\n")
                    continue
                chan.send(b"logout\r\n")
                break

            # 提權成持續 shell（sudo su / sudo -i / sudo bash 等）：切換身分,不送 LLM
            esc = detect_escalation(command)
            if esc is not None:
                toks = command.split()
                login_shell = ("-i" in toks) or ("--login" in toks) or ("-l" in toks) \
                    or ("su" in toks and "-" in toks)
                _SESSION_MGR.push_user(session_id, esc, login_shell=login_shell)
                logger.command(session_id, command, "", "privilege_escalation", 0.95, True)
                continue

            # cd handled entirely in Layer 1
            if command == "cd" or command.startswith("cd "):
                new_dir, err = _SESSION_MGR.handle_cd(session_id, command)
                output = err
                intent, conf, cache_hit = "reconnaissance", 0.9, True
            else:
                session_data = _SESSION_MGR.get(session_id)
                eff_user = _SESSION_MGR.effective_user(session_id)
                rich_history = [
                    f"$ {cmd}\n{resp}" if resp.strip() else f"$ {cmd}"
                    for cmd, resp in session_data["history_pairs"]
                ] or session_data["history"]

                result = llm_client.respond(
                    session_id=session_id,
                    protocol="ssh",
                    command=command,
                    current_dir=session_data["current_dir"],
                    user=eff_user,
                    history=rich_history,
                    attacker_ip=addr[0],
                )
                output = result["response"]
                intent = result["intent"]
                conf = result["confidence"]
                cache_hit = result["cache_hit"]
                _SESSION_MGR.push_history_with_response(session_id, command, output)

            if output and not output.endswith("\n"):
                output += "\n"

            logger.command(session_id, command, output, intent, conf, cache_hit)

            try:
                for ch in output:
                    if ch == "\n":
                        chan.send(b"\r\n")
                    else:
                        chan.send(ch.encode())
            except Exception:
                pass

        _end_session()
    except Exception as e:
        print(f"[ssh] connection error {addr}: {e}")
    finally:
        _end_session()
        if transport:
            try:
                transport.close()
            except Exception:
                pass


def run(host: str = "0.0.0.0") -> None:
    port = int(os.getenv("SSH_PORT", "2222"))
    logger = Logger()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(10)
    print(f"[ssh] listening on {host}:{port}")
    while True:
        client_sock, addr = sock.accept()
        print(f"[ssh] connection from {addr}")
        threading.Thread(target=_handle_client, args=(client_sock, addr, logger), daemon=True).start()


if __name__ == "__main__":
    run()
