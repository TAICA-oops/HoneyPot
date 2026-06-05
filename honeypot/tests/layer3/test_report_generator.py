import pytest
from unittest.mock import patch


def _seed_session(db_path, threat_level="High"):
    """在 tmp_db 插入一筆測試 session + 一條指令。"""
    from layer2.db import get_conn, init_db
    init_db(db_path)
    conn = get_conn(db_path)
    conn.execute(
        "INSERT INTO sessions (session_id, protocol, attacker_ip, threat_level) "
        "VALUES (?,?,?,?)",
        ("sess-001", "ssh", "1.2.3.4", threat_level),
    )
    conn.execute(
        "INSERT INTO commands "
        "(session_id, command, response, intent, confidence, cache_hit) "
        "VALUES (?,?,?,?,?,?)",
        ("sess-001", "ls /", "", "reconnaissance", 0.95, 0),
    )
    conn.commit()
    conn.close()


def test_threat_level_in_prompt_content(tmp_db):
    """DB 的 threat_level 必須出現在傳給 LLM 的 user message 裡。"""
    _seed_session(tmp_db, threat_level="Critical")

    captured = {}

    def fake_generate(messages, temperature=0.1, model=None, **kwargs):
        captured["messages"] = messages
        return "# Fake Report"

    with patch("layer3.report_generator.generate", side_effect=fake_generate):
        from layer3.report_generator import generate_report
        generate_report("sess-001")

    user_msg = captured["messages"][1]["content"]
    assert "Critical" in user_msg, (
        f"Expected DB threat_level 'Critical' in prompt, got:\n{user_msg[:300]}"
    )


def test_threat_level_authoritative_in_system_prompt():
    """System prompt 必須指示 LLM 威脅等級已確定，不要重新判斷。"""
    from layer3.report_generator import _REPORT_SYSTEM
    system_lower = _REPORT_SYSTEM.lower()
    assert any(phrase in system_lower for phrase in [
        "already determined",
        "do not re-determine",
        "authoritative",
    ]), (
        "System prompt 應包含 'already determined' / "
        "'do not re-determine' / 'authoritative' 其中一個"
    )


def test_log_wrapped_in_fenced_block(tmp_db):
    """Log 內容必須被包在 fenced block 裡，與 prompt 指令隔離。"""
    _seed_session(tmp_db)

    captured = {}

    def fake_generate(messages, temperature=0.1, model=None, **kwargs):
        captured["messages"] = messages
        return "# Fake Report"

    with patch("layer3.report_generator.generate", side_effect=fake_generate):
        from layer3.report_generator import generate_report
        generate_report("sess-001")

    user_msg = captured["messages"][1]["content"]
    assert "```log\n" in user_msg, "Log 內容應以 ```log 開頭的 fenced block 包住"
    assert "\n```" in user_msg, "Fenced block 應有結尾 ```"
    # 確認 log 內容在 fenced block 內部
    start = user_msg.index("```log\n") + len("```log\n")
    end = user_msg.index("\n```", start)
    log_body = user_msg[start:end]
    assert "ls /" in log_body, "種子指令應在 fenced block 裡"


def test_anti_injection_in_system_prompt():
    """System prompt 必須包含防注入聲明。"""
    from layer3.report_generator import _REPORT_SYSTEM
    system_lower = _REPORT_SYSTEM.lower()
    assert any(phrase in system_lower for phrase in [
        "untrusted",
        "adversarial",
        "ignore any instructions",
        "do not follow",
    ]), "System prompt 應包含防注入聲明（untrusted / adversarial / ignore any instructions）"
