import os
import socket
import threading
import time
import uuid
import paramiko
from dotenv import load_dotenv
from layer1.session_manager import SessionManager
from layer1 import llm_client
from layer1.logger import Logger

load_dotenv()

HOST_KEY_PATH = ".ssh_host_key"

_VALID_CREDS: dict[str, list[str]] = {
    "admin":   ["admin", "password", "123456", "admin123", "Admin@123"],
    "root":    ["toor", "root", "password", "123456", "P@ssw0rd"],
    "deploy":  ["deploy", "deploy123", "d3ploy"],
    "ubuntu":  ["ubuntu", "ubuntu123"],
    "dbadmin": ["Sup3rS3cr3t!2019", "dbadmin"],
}

def _host_key() -> paramiko.RSAKey:
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key

_SESSION_MGR = SessionManager()
_HOST_KEY = _host_key()

class _ServerInterface(paramiko.ServerInterface):
    def __init__(self, addr_ip: str):
        self.username = "admin"
        self.addr_ip = addr_ip
        self._shell_ready = threading.Event()

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
    def _gen():
        try:
            from layer3.report_generator import generate_report
            generate_report(session_id)
            print(f"[ssh] report generated for {session_id}")
        except Exception as e:
            print(f"[ssh] report generation failed: {e}")
    threading.Thread(target=_gen, daemon=True).start()


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
        transport.get_security_options().kex = [
            'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
            'diffie-hellman-group14-sha256', 'diffie-hellman-group14-sha1',
        ]
        transport.add_server_key(_HOST_KEY)
        server = _ServerInterface(addr[0])
        transport.start_server(server=server)

        chan = transport.accept(30)
        if chan is None:
            return
        server._shell_ready.wait(10)

        session_id = str(uuid.uuid4())
        _SESSION_MGR.create(session_id, server.username, addr[0])
        logger.session_start(session_id, "ssh", addr[0])

        chan.send(
            b"\r\nWelcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)\r\n"
            b" * Documentation:  https://help.ubuntu.com\r\n\r\n"
        )

        buf = ""
        timeout = int(os.getenv("SESSION_TIMEOUT_SECONDS", "600"))
        chan.settimeout(timeout)

        while True:
            session = _SESSION_MGR.get(session_id)
            prompt = f"{server.username}@web-server-01:{session['current_dir']}$ "
            chan.send(prompt.encode())

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

                if text in ("\r", "\n", "\r\n"):
                    chan.send(b"\r\n")
                    break
                elif text in ("\x7f", "\x08"):
                    if buf:
                        buf = buf[:-1]
                        chan.send(b"\x08 \x08")
                elif text == "\x03":
                    buf = ""
                    chan.send(b"^C\r\n")
                    break
                elif text == "\x04":
                    chan.send(b"logout\r\n")
                    _end_session()
                    return
                else:
                    buf += text
                    chan.send(text.encode())

            command = buf.strip()
            buf = ""

            if not command:
                continue

            if command in ("exit", "quit", "logout"):
                chan.send(b"logout\r\n")
                break

            # cd handled entirely in Layer 1
            if command == "cd" or command.startswith("cd "):
                new_dir, err = _SESSION_MGR.handle_cd(session_id, command)
                output = err
                intent, conf, cache_hit = "reconnaissance", 0.9, True
            else:
                session_data = _SESSION_MGR.get(session_id)
                rich_history = [
                    f"$ {cmd}\n{resp}" if resp.strip() else f"$ {cmd}"
                    for cmd, resp in session_data["history_pairs"]
                ] or session_data["history"]

                result = llm_client.respond(
                    session_id=session_id,
                    protocol="ssh",
                    command=command,
                    current_dir=session_data["current_dir"],
                    user=server.username,
                    history=rich_history,
                )
                output = result["response"]
                intent = result["intent"]
                conf = result["confidence"]
                cache_hit = result["cache_hit"]
                _SESSION_MGR.push_history_with_response(session_id, command, output)

            for ch in output:
                if ch == "\n":
                    chan.send(b"\r\n")
                else:
                    chan.send(ch.encode())

            logger.command(session_id, command, output, intent, conf, cache_hit)

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
