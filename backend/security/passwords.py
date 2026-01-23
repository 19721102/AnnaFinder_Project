from __future__ import annotations

from passlib.context import CryptContext

pwd_context = CryptContext(
    schemes=["argon2", "pbkdf2_sha256"],
    deprecated="auto",
    pbkdf2_sha256__default_rounds=120000,
)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)
