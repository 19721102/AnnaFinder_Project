from pathlib import Path

import models  # noqa: F401  # ensure models are registered with Base

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text

from db.base import Base
from db.session import DATABASE_URL, engine


EXPECTED_TABLES = {
    "users",
    "families",
    "family_members",
    "locations",
    "items",
    "tags",
    "item_tag_links",
    "events",
    "attachments",
    "audit_log",
}


def _get_alembic_config() -> Config:
    root = Path(__file__).resolve().parents[1]
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", DATABASE_URL)
    config.set_main_option("script_location", str(root / "alembic"))
    return config


def test_metadata_defines_expected_tables():
    tables = set(Base.metadata.tables.keys())
    assert EXPECTED_TABLES.issubset(tables)


def test_can_connect_to_database():
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
    assert result == 1


@pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not configured")
def test_alembic_upgrade_and_downgrade():
    config = _get_alembic_config()
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    command.upgrade(config, "head")
