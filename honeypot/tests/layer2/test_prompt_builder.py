from layer2.prompt_builder import build_messages
from shared import fake_fs

def test_system_prompt_contains_persona():
    msgs = build_messages("ls", "/etc", "admin", [])
    system = msgs[0]["content"]
    assert "Ubuntu 18.04" in system
    assert "web-server-01" in system


def test_prompt_does_not_hardcode_user_identity():
    # 不可寫死 USER=admin / HOME=/home/admin,否則登入 dbadmin 時 env / echo $USER 會穿幫
    system = build_messages("env", "/home/dbadmin", "dbadmin", [])[0]["content"]
    assert "USER=admin" not in system
    assert "HOME=/home/admin" not in system


def test_prompt_provides_current_system_time():
    import datetime
    msgs = build_messages("date", "/", "admin", [])
    user_msg = msgs[-1]["content"]
    # 系統時間隨請求動態提供（讓 LLM 生成的日誌時間貼近現在,而非寫死 2023）
    assert "System time:" in user_msg
    assert str(datetime.datetime.now(datetime.timezone.utc).year) in user_msg


def test_prompt_has_no_timezone_contradiction():
    # 系統輸出 UTC,prompt 不該又宣稱 UTC+8
    system = build_messages("date", "/", "admin", [])[0]["content"]
    assert "UTC+8" not in system


def test_prompt_env_matches_canonical_and_no_example_aws_key():
    system = build_messages("cat /var/www/html/.env", "/", "admin", [])[0]["content"]
    assert fake_fs.AWS_KEY in system
    assert "AKIAIOSFODNN7EXAMPLE" not in system


def test_prompt_includes_all_canonical_users():
    system = build_messages("id", "/", "admin", [])[0]["content"]
    for u in ("root", "admin", "deploy", "backup", "dbadmin", "ubuntu"):
        assert u in system


def test_user_message_reflects_effective_user():
    user_msg = build_messages("whoami", "/root", "root", [])[-1]["content"]
    assert "Current user: root" in user_msg

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
