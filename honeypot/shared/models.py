from pydantic import BaseModel, field_validator

VALID_INTENTS = {
    "reconnaissance", "privilege_escalation", "data_exfiltration",
    "persistence", "lateral_movement", "unknown"
}

class RespondRequest(BaseModel):
    session_id: str
    protocol: str
    command: str
    current_dir: str
    user: str
    history: list[str] = []

class RespondResponse(BaseModel):
    session_id: str
    response: str
    intent: str
    confidence: float
    cache_hit: bool

    @field_validator("intent")
    @classmethod
    def intent_must_be_valid(cls, v):
        if v not in VALID_INTENTS:
            raise ValueError(f"intent must be one of {VALID_INTENTS}")
        return v

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        return v
