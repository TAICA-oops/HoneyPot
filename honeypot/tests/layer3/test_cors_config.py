"""Stats API 的 CORS 來源可由環境變數設定（部署時可鎖定,本地預設開放）。"""
from layer3 import stats_api


def test_cors_origins_default_is_wildcard(monkeypatch):
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    assert stats_api._cors_origins() == ["*"]


def test_cors_origins_parsed_from_env(monkeypatch):
    monkeypatch.setenv("CORS_ORIGINS", "https://a.example, https://b.example")
    assert stats_api._cors_origins() == ["https://a.example", "https://b.example"]
