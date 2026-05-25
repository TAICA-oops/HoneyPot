import os
import pytest

@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    os.environ["DB_PATH"] = db_path
    return db_path
