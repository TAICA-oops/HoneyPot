import os
import pytest

@pytest.fixture
def tmp_db(tmp_path):
    original = os.environ.get("DB_PATH")
    db_path = str(tmp_path / "test.db")
    os.environ["DB_PATH"] = db_path
    yield db_path
    if original is not None:
        os.environ["DB_PATH"] = original
    else:
        os.environ.pop("DB_PATH", None)
