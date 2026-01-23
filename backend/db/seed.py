from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from models.entities import Event, Family, FamilyMember, User
from backend.permissions import ROLE_MEMBER, ROLE_OWNER, ROLE_VIEWER
from backend.security.passwords import hash_password

SEED_USERS = (
    ("demo@annafinder.local", "Demo1234!", ROLE_OWNER),
    ("viewer@annafinder.local", "Viewer1234!", ROLE_VIEWER),
    ("reset@annafinder.local", "Reset1234!", ROLE_MEMBER),
)


def _now_iso() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_user(session: Session, email: str, password: str) -> User:
    stmt = select(User).filter_by(email=email)
    user = session.scalar(stmt)
    if not user:
        user = User(email=email, password_hash=hash_password(password))
        session.add(user)
        session.flush()
    return user


def _ensure_membership(session: Session, family: Family, user: User, role: str) -> None:
    stmt = select(FamilyMember).filter_by(family_id=family.id, user_id=user.id)
    membership = session.scalar(stmt)
    if not membership:
        membership = FamilyMember(
            family_id=family.id,
            user_id=user.id,
            role=role,
            is_owner=role == ROLE_OWNER,
        )
        session.add(membership)


def seed_demo_data(session: Session) -> None:
    family = session.scalar(select(Family).filter_by(name="Demo Family"))
    if not family:
        family = Family(name="Demo Family", description="Demo family")
        session.add(family)
        session.flush()
    for email, password, role in SEED_USERS:
        user = _ensure_user(session, email, password)
        user.email_verified_at = user.email_verified_at or _now_iso()
        _ensure_membership(session, family, user, role)
    event_stmt = select(Event).filter_by(kind="seed", family_id=family.id)
    if not session.scalar(event_stmt):
        seed_event = Event(
            family_id=family.id,
            kind="seed",
            message="Demo data seeded",
            details="Initial demo entities",
        )
        session.add(seed_event)
    session.commit()
