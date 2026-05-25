import os
import httpx
from dotenv import load_dotenv

load_dotenv()

def get_ollama_host() -> str:
    return os.getenv("OLLAMA_HOST", "http://localhost:11434")

def get_model() -> str:
    return os.getenv("OLLAMA_MODEL", "llama3.1")

def generate(messages: list[dict], stream: bool = False) -> str:
    """Send messages to Ollama and return the full response text."""
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": get_model(),
        "messages": messages,
        "stream": False,
    }
    try:
        resp = httpx.post(url, json=payload, timeout=15.0)
        resp.raise_for_status()
        return resp.json()["message"]["content"]
    except httpx.TimeoutException:
        return "bash: command timed out\n"
    except Exception:
        return "command not found\n"

def generate_streaming(messages: list[dict]):
    """Yield response tokens one at a time for SSH streaming."""
    url = get_ollama_host() + "/api/chat"
    payload = {
        "model": get_model(),
        "messages": messages,
        "stream": True,
    }
    try:
        with httpx.stream("POST", url, json=payload, timeout=20.0) as resp:
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
