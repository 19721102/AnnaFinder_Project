from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from jwt import PyJWTError
from pydantic import BaseModel, Field, field_validator

from backend.security.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from backend.security.passwords import hash_password, verify_password

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[3]
ENV = os.getenv("ANNAFINDER_ENV", "dev").strip().lower()
DB_PATH = BASE_DIR / ("annafinder_test.db" if ENV == "test" else "annafinder.db")


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA busy_timeout = 10000")
    except sqlite3.DatabaseError:
        pass
    return con


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_user_by_email(email: str) -> Optional[sqlite3.Row]:
    con = _connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
    row = cur.fetchone()
    con.close()
    return row


def _get_user_by_id(user_id: str) -> Optional[sqlite3.Row]:
    con = _connect()
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    con.close()
    return row


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise ValueError("invalid email")
    return email


class RegisterPayload(BaseModel):
    email: str
    password: str = Field(..., min_length=8)
    display_name: Optional[str] = None

    @field_validator("email", mode="before")
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)


class RegisterResponse(BaseModel):
    id: str
    email: str
    display_name: Optional[str] = None


class LoginPayload(BaseModel):
    email: str
    password: str = Field(..., min_length=8)

    @field_validator("email", mode="before")
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_sec: int


class RefreshPayload(BaseModel):
    refresh_token: str


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterPayload) -> RegisterResponse:
    email = payload.email.lower()
    if _get_user_by_email(email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    hashed = hash_password(payload.password)
    created_at = _now_iso()
    user_id = str(uuid.uuid4())
    con = _connect()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO users (id, email, password_hash, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (user_id, email, hashed, created_at),
    )
    con.commit()
    con.close()
    return RegisterResponse(id=user_id, email=email, display_name=payload.display_name)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginPayload) -> TokenResponse:
    user = _get_user_by_email(payload.email.lower())
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token, access_ttl = create_access_token(user["id"])
    refresh_token, _ = create_refresh_token(user["id"])
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_sec=access_ttl,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshPayload) -> TokenResponse:
    try:
        decoded = decode_token(payload.refresh_token)
    except PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc
    if decoded.get("token_type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    user_id = decoded.get("sub")
    if not user_id or not _get_user_by_id(user_id):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    access_token, access_ttl = create_access_token(user_id)
    refresh_token, _ = create_refresh_token(user_id)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_sec=access_ttl,
    )
