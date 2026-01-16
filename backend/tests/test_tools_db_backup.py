from pathlib import Path
import os
import sys
import pytest

os.environ.setdefault("ANNAFINDER_ENV", "test")
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

from backend.tools import db_backup  # noqa: E402


def test_vacuum_into_sql_escapes_single_quote():
    sql = db_backup.vacuum_into_sql("C:\\tmp\\O'Connor.db")
    assert "O''Connor.db" in sql
    assert sql.startswith("VACUUM INTO '")
    assert sql.endswith("'")


def test_vacuum_into_sql_requires_path():
    with pytest.raises(ValueError):
        db_backup.vacuum_into_sql("")
