from __future__ import annotations

import sqlite3
from typing import Any, Dict
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError

from backend.db.users import get_user_by_id
from backend.security.jwt import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def _db_connection() -> sqlite3.Connection:
    from backend.main import db as get_db

    return get_db()


def _normalize_uuid_column(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return str(UUID(bytes=value))
    if value is None:
        return ""
    return str(value)


def get_current_user(token: str = Depends(oauth2_scheme)) -> sqlite3.Row:
    try:
        payload = decode_token(token)
    except PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        ) from exc
    if payload.get("token_type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access tokens only",
        )
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
        )
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if "is_active" in user and not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user",
        )
    return user


def require_family_access(
    family_id: UUID,
    user: sqlite3.Row = Depends(get_current_user),
) -> Dict[str, str]:
    user_id = UUID(user["id"])
    family_str = str(family_id)
    user_str = str(user_id)
    connection = _db_connection()
    family_values = (family_str, family_id.hex, family_id.bytes)
    user_values = (user_str, user_id.hex, user_id.bytes)
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT family_id, user_id, role
            FROM family_members
            WHERE (family_id = ? OR family_id = ? OR family_id = ?)
              AND (user_id = ? OR user_id = ? OR user_id = ?)
            """,
            family_values + user_values,
        )
        membership = cursor.fetchone()
    finally:
        connection.close()
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Family not found or access denied",
        )
    return {
        "family_id": _normalize_uuid_column(membership["family_id"]),
        "user_id": _normalize_uuid_column(membership["user_id"]),
        "role": membership["role"],
    }
