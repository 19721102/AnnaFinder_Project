from __future__ import annotations

import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response, status
from jwt import PyJWTError
from pydantic import BaseModel, Field, field_validator

from backend.security.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from backend.security.passwords import hash_password, verify_password
from backend.services.audit import write_audit

router = APIRouter()

BASE_DIR = Path(__file__).resolve().parents[3]
ENV = os.getenv("ANNAFINDER_ENV", "dev").strip().lower()
DB_PATH = BASE_DIR / ("annafinder_test.db" if ENV == "test" else "annafinder.db")
CSRF_COOKIE_NAME = "anna_csrf"
CSRF_TTL_SECONDS = 60 * 60 * 12


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


def ensure_csrf_cookie(response: Response, request: Request, rotate: bool = False) -> str:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if rotate or not token:
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            httponly=False,
            samesite="strict",
            secure=ENV == "prod",
            max_age=CSRF_TTL_SECONDS,
            path="/",
        )
    return token


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
def register(payload: RegisterPayload, request: Request) -> RegisterResponse:
    email = payload.email.lower()
    if _get_user_by_email(email):
        write_audit(
            event_type="auth.register",
            success=False,
            request=request,
            payload={"email": email},
        )
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
    write_audit(
        event_type="auth.register",
        actor_user_id=uuid.UUID(user_id),
        success=True,
        request=request,
        payload={"email": email},
    )
    return RegisterResponse(id=user_id, email=email, display_name=payload.display_name)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginPayload, request: Request, response: Response) -> TokenResponse:
    user = _get_user_by_email(payload.email.lower())
    if not user or not verify_password(payload.password, user["password_hash"]):
        write_audit(
            event_type="auth.login",
            success=False,
            request=request,
            payload={"email": payload.email.lower()},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access_token, access_ttl = create_access_token(user["id"])
    refresh_token, _ = create_refresh_token(user["id"])
    write_audit(
        event_type="auth.login",
        actor_user_id=uuid.UUID(user["id"]),
        success=True,
        request=request,
        payload={"email": payload.email.lower()},
    )
    ensure_csrf_cookie(response, request, rotate=True)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_sec=access_ttl,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(payload: RefreshPayload, request: Request) -> TokenResponse:
    try:
        decoded = decode_token(payload.refresh_token)
    except PyJWTError as exc:
        write_audit(
            event_type="auth.refresh",
            success=False,
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token") from exc
    if decoded.get("token_type") != "refresh":
        write_audit(
            event_type="auth.refresh",
            success=False,
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    user_id = decoded.get("sub")
    if not user_id or not _get_user_by_id(user_id):
        write_audit(
            event_type="auth.refresh",
            success=False,
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    access_token, access_ttl = create_access_token(user_id)
    refresh_token, _ = create_refresh_token(user_id)
    write_audit(
        event_type="auth.refresh",
        actor_user_id=uuid.UUID(user_id),
        success=True,
        request=request,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_sec=access_ttl,
    )
