from layer2.prompt_builder import build_messages

def test_system_prompt_contains_persona():
    msgs = build_messages("ls", "/etc", "admin", [])
    system = msgs[0]["content"]
    assert "Ubuntu 18.04" in system
    assert "web-server-01" in system

def test_user_message_contains_command():
    msgs = build_messages("cat /etc/passwd", "/etc", "root", ["whoami", "id"])
    user_msg = msgs[-1]["content"]
    assert "cat /etc/passwd" in user_msg
    assert "/etc" in user_msg

def test_history_included():
    msgs = build_messages("ls", "/", "admin", ["whoami", "id"])
    user_msg = msgs[-1]["content"]
    assert "whoami" in user_msg
    assert "id" in user_msg
