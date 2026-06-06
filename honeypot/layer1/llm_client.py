import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def _engine_url() -> str:
    port = os.getenv("LLM_ENGINE_PORT", "8000")
    return f"http://127.0.0.1:{port}"

def respond(
    session_id: str,
    protocol: str,
    command: str,
    current_dir: str,
    user: str,
    history: list[str],
    attacker_ip: str = "",
) -> dict:
    payload = {
        "session_id": session_id,
        "protocol": protocol,
        "command": command,
        "current_dir": current_dir,
        "user": user,
        "history": history,
        "attacker_ip": attacker_ip,
    }
    try:
        r = httpx.post(_engine_url() + "/respond", json=payload, timeout=20.0)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {
            "session_id": session_id,
            "response": "command not found\n",
            "intent": "unknown",
            "confidence": 0.0,
            "cache_hit": False,
        }
