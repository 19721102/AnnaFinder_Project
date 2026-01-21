from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

BASE_DIR = Path(__file__).resolve().parents[1]
ANNAFINDER_ENV = os.getenv("ANNAFINDER_ENV", "dev").strip().lower()
default_db = "annafinder_test.db" if ANNAFINDER_ENV == "test" else "annafinder.db"
DEFAULT_SQLITE_URL = f"sqlite:///{(BASE_DIR / default_db).as_posix()}"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_SQLITE_URL)

_connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(bind=engine, class_=Session, expire_on_commit=False, future=True)


def get_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def try_connect(timeout_seconds: int = 5) -> None:
    try:
        with engine.connect() as conn:
            conn.execute("SELECT 1")
            conn.commit()
    except OperationalError as exc:
        raise RuntimeError("Could not connect to the database") from exc
