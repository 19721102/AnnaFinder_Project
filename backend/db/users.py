from __future__ import annotations

import sqlite3
from typing import Optional


def _db_connection() -> sqlite3.Connection:
    from backend.main import db as get_db

    return get_db()


def get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    con = _db_connection()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    row = cur.fetchone()
    con.close()
    return row


def get_user_by_id(user_id: str) -> Optional[sqlite3.Row]:
    con = _db_connection()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    con.close()
    return row


def create_user(user_id: str, email: str, password_hash: str, created_at: str) -> None:
    con = _db_connection()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO users (id, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, email, password_hash, created_at),
    )
    con.commit()
    con.close()
