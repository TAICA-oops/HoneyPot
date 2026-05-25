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

def _host_key() -> paramiko.RSAKey:
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key

_SESSION_MGR = SessionManager()
_HOST_KEY = _host_key()

class _ServerInterface(paramiko.ServerInterface):
    def __init__(self):
        self.username = "admin"
        self._shell_ready = threading.Event()

    def check_auth_password(self, username, password):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

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
    intents = [r[0] for r in rows]
    if "privilege_escalation" in intents or "data_exfiltration" in intents:
        return "High"
    if "persistence" in intents or "lateral_movement" in intents:
        return "Medium"
    return "Low"


def _handle_client(sock: socket.socket, addr: tuple, logger: Logger) -> None:
    try:
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7"
        transport.add_server_key(_HOST_KEY)
        server = _ServerInterface()
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
                    return
                if not data:
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
                    logger.session_end(session_id, _compute_threat_level(session_id))
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
            if command.startswith("cd"):
                new_dir, err = _SESSION_MGR.handle_cd(session_id, command)
                output = err
                intent, conf, cache_hit = "reconnaissance", 0.9, True
            else:
                _SESSION_MGR.push_history(session_id, command)
                result = llm_client.respond(
                    session_id=session_id,
                    protocol="ssh",
                    command=command,
                    current_dir=_SESSION_MGR.get(session_id)["current_dir"],
                    user=server.username,
                    history=_SESSION_MGR.get(session_id)["history"],
                )
                output = result["response"]
                intent = result["intent"]
                conf = result["confidence"]
                cache_hit = result["cache_hit"]

            for ch in output:
                if ch == "\n":
                    chan.send(b"\r\n")
                else:
                    chan.send(ch.encode())

            logger.command(session_id, command, output, intent, conf, cache_hit)

        logger.session_end(session_id, _compute_threat_level(session_id))
    except Exception as e:
        print(f"[ssh] connection error {addr}: {e}")
    finally:
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
