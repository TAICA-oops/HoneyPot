import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")

def get_model() -> str:
    return os.getenv("OLLAMA_MODEL", "llama3.1")

def get_report_model() -> str:
    return os.getenv("OLLAMA_REPORT_MODEL", os.getenv("OLLAMA_MODEL", "llama3.1"))

def generate(messages: list[dict], temperature: float = 0.1, model: str | None = None) -> str:
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": model or get_model(),
        "messages": messages,
        "stream": False,
        "keep_alive": -1,
        "options": {"temperature": temperature},
    }
    try:
        resp = httpx.post(url, json=payload, timeout=30.0)
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except httpx.TimeoutException:
        return "bash: command timed out\n"
    except Exception:
        return "command not found\n"

def generate_streaming(messages: list[dict], temperature: float = 0.1):
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": get_model(),
        "messages": messages,
        "stream": True,
        "keep_alive": -1,
        "options": {"temperature": temperature},
    }
    try:
        with httpx.stream("POST", url, json=payload, timeout=30.0) as resp:
            import json
            for line in resp.iter_lines():
                if line:
                    data = json.loads(line)
                    token = data.get("message", {}).get("content", "")
                    if token:
                        yield token
                    if data.get("done"):
                        break
    except Exception:
        yield "command not found\n"
