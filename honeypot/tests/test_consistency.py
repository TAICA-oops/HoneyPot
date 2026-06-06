"""跨層一致性測試 —— 防止 SSH / HTTP / LLM prompt 的假資產各說各話。"""
from shared import fake_fs
from layer2 import cache


def test_env_has_single_source_of_truth():
    # SSH `cat /var/www/html/.env` 和共用常數必須是同一份內容
    assert cache._BAIT_ENV is fake_fs.ENV_FILE


def test_http_and_ssh_env_are_identical():
    # 攻擊者從 HTTP /.env 與 SSH cat .env 拿到的必須一模一樣
    from layer1 import http_server
    assert http_server._FAKE_ENV is fake_fs.ENV_FILE


def test_aws_key_is_not_the_public_example_key():
    # AWS 文件範例金鑰一眼就被認出是假的 → 不可使用
    assert "AKIAIOSFODNN7EXAMPLE" not in fake_fs.ENV_FILE
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in fake_fs.ENV_FILE
    # 但仍要是合法格式的假金鑰
    assert "AKIA" in fake_fs.ENV_FILE
    assert "AWS_SECRET=" in fake_fs.ENV_FILE


def test_db_password_consistent_across_assets():
    # .env / wp-config.php / .my.cnf / backup 都引用同一組 DB 密碼
    assert fake_fs.DB_PASSWORD in fake_fs.ENV_FILE
    assert fake_fs.DB_PASSWORD in fake_fs.WP_CONFIG
    assert fake_fs.DB_PASSWORD in fake_fs.MY_CNF
