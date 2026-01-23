"""add user full name

Revision ID: cc7dd1621c50
Revises: 8000c15b0eaf
Create Date: 2026-01-22 01:43:15.949307

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "cc7dd1621c50"
down_revision: str = "8000c15b0eaf"
branch_labels = None
depends_on = None


def _column_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    return any(col["name"] == column for col in insp.get_columns(table))


def upgrade() -> None:
    """Upgrade schema."""
    if not _column_exists("users", "full_name"):
        op.add_column(
            "users",
            sa.Column("full_name", sa.String(length=192), nullable=True),
        )


def downgrade() -> None:
    """Downgrade schema."""
    if _column_exists("users", "full_name"):
        op.drop_column("users", "full_name")
