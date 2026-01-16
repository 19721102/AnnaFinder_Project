import pytest

import backend.main as backend_main
from backend.main import validate_identifier


@pytest.mark.parametrize("value", ["", "123start", "has-dash", "weird;name", "with space"])
def test_validate_identifier_rejects_invalid_names(value):
    with pytest.raises(ValueError):
        validate_identifier(value)


@pytest.mark.parametrize("value", ["valid_name", "Column1", "_underscore", "Another_Column"])
def test_validate_identifier_accepts_valid_names(value):
    assert validate_identifier(value) == value


def test_ensure_column_rejects_invalid_type():
    con = backend_main.db()
    try:
        with pytest.raises(ValueError):
            backend_main.ensure_column(con, "users", "extra_flag", "INVALID_TYPE")
    finally:
        con.close()


def test_ensure_column_rejects_unknown_table():
    con = backend_main.db()
    try:
        with pytest.raises(ValueError):
            backend_main.ensure_column(con, "unknown_table", "extra", "TEXT")
    finally:
        con.close()
