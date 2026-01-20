from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Any, Dict, Tuple

import jwt

JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALGORITHM = os.getenv("JWT_ALG", "HS256")
ACCESS_TOKEN_TTL_MIN = int(os.getenv("ACCESS_TOKEN_TTL_MIN", "15"))
REFRESH_TOKEN_TTL_DAYS = int(os.getenv("REFRESH_TOKEN_TTL_DAYS", "14"))
ACCESS_TOKEN_TTL_SECONDS = ACCESS_TOKEN_TTL_MIN * 60
REFRESH_TOKEN_TTL_SECONDS = REFRESH_TOKEN_TTL_DAYS * 24 * 3600


def _now() -> datetime:
    return datetime.utcnow()


def _build_payload(user_id: str, token_type: str, expires_delta: timedelta) -> Dict[str, Any]:
    now = _now()
    return {
        "sub": user_id,
        "iss": "annafinder",
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "token_type": token_type,
    }


def _encode(token_type: str, user_id: str, expires_delta: timedelta) -> Tuple[str, int]:
    payload = _build_payload(user_id, token_type, expires_delta)
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    expires_in = int(expires_delta.total_seconds())
    return token, expires_in


def create_access_token(user_id: str) -> Tuple[str, int]:
    return _encode("access", user_id, timedelta(minutes=ACCESS_TOKEN_TTL_MIN))


def create_refresh_token(user_id: str) -> Tuple[str, int]:
    return _encode("refresh", user_id, timedelta(days=REFRESH_TOKEN_TTL_DAYS))


def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"require_sub": True},
    )
