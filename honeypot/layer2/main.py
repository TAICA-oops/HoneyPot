from fastapi import FastAPI
from layer2.cache import CacheHandler
from layer2.ollama_client import generate
from layer2.prompt_builder import build_messages
from layer2.intent_classifier import classify
from shared.models import RespondRequest, RespondResponse

app = FastAPI(title="HoneyPot LLM Engine")
_cache = CacheHandler()

# cross-session consistency: cache LLM responses for read-only filesystem commands
_dynamic_fs: dict[tuple, str] = {}

_READ_CMDS = {"ls", "cat", "find", "file", "stat", "readlink", "head", "tail"}

@app.post("/respond", response_model=RespondResponse)
def respond(req: RespondRequest) -> RespondResponse:
    cached = _cache.handle(req.command, req.current_dir, req.user, req.history)
    if cached is not None:
        intent, conf = classify(req.command)
        return RespondResponse(
            session_id=req.session_id,
            response=cached,
            intent=intent,
            confidence=conf,
            cache_hit=True,
        )

    fs_key = (req.command.strip(), req.current_dir, req.user)
    if fs_key in _dynamic_fs:
        intent, conf = classify(req.command)
        return RespondResponse(
            session_id=req.session_id,
            response=_dynamic_fs[fs_key],
            intent=intent,
            confidence=conf,
            cache_hit=True,
        )

    messages = build_messages(req.command, req.current_dir, req.user, req.history)
    response_text = generate(messages)
    intent, conf = classify(req.command)

    cmd_name = req.command.strip().split()[0] if req.command.strip() else ""
    if cmd_name in _READ_CMDS:
        _dynamic_fs[fs_key] = response_text

    return RespondResponse(
        session_id=req.session_id,
        response=response_text,
        intent=intent,
        confidence=conf,
        cache_hit=False,
    )

@app.get("/health")
def health():
    return {"status": "ok"}
