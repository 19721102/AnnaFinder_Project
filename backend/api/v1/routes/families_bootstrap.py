from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.api.v1.deps.auth import get_current_user, require_family_access
from backend.db.session import get_session
from models.entities import Family

router = APIRouter()


class FamilyCreateIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)


class FamilySummaryOut(BaseModel):
    family_id: UUID
    name: str
    role: str


class FamiliesListOut(BaseModel):
    families: list[FamilySummaryOut]


class FamilyDetailOut(BaseModel):
    family_id: UUID
    name: str
    created_at: str


@router.post("/families", response_model=FamilySummaryOut, status_code=status.HTTP_201_CREATED)
def create_family(
    payload: FamilyCreateIn,
    user=Depends(get_current_user),
    session: Session = Depends(get_session),
) -> FamilySummaryOut:
    user_id = UUID(user["id"])
    family = Family(name=payload.name.strip())
    session.add(family)
    session.flush()
    _insert_family_membership(session, family.id, user_id, "owner", True)
    session.commit()
    return FamilySummaryOut(family_id=family.id, name=family.name, role="owner")


@router.get("/families", response_model=FamiliesListOut)
def list_families(user=Depends(get_current_user), session: Session = Depends(get_session)) -> FamiliesListOut:
    user_id = UUID(user["id"])
    connection = _db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            SELECT fm.family_id AS family_id, fm.user_id AS user_id, fm.role
            FROM family_members fm
            WHERE fm.user_id = ? OR fm.user_id = ? OR fm.user_id = ?
            ORDER BY fm.created_at DESC
            """,
            (str(user_id), user_id.hex, user_id.bytes),
        )
        rows = cursor.fetchall()
    finally:
        connection.close()
    families: list[FamilySummaryOut] = []
    for row in rows:
        family_id_value = _normalize_uuid_column(row["family_id"])
        try:
            family_obj = session.get(Family, UUID(family_id_value))
        except ValueError:
            continue
        if not family_obj:
            continue
        families.append(
            FamilySummaryOut(
                family_id=UUID(family_id_value),
                name=family_obj.name,
                role=row["role"],
            )
        )
    return FamiliesListOut(families=families)


@router.get("/families/{family_id}", response_model=FamilyDetailOut)
def get_family(
    family_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> FamilyDetailOut:
    family = session.get(Family, family_id)
    if not family:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Family not found or access denied")
    return FamilyDetailOut(
        family_id=family.id,
        name=family.name,
        created_at=family.created_at.isoformat(),
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _insert_family_membership(session: Session, family_id: uuid.UUID, user_id: uuid.UUID, role: str, is_owner: bool) -> None:
    ts = _now_iso()
    table_info = session.execute(text("PRAGMA table_info('family_members')")).all()
    columns = {row[1] for row in table_info}
    include_name = "name" in columns
    family_id_value = str(family_id)
    user_id_value = str(user_id)
    if include_name:
        session.execute(
            text(
                """
                INSERT INTO family_members (
                    id, family_id, user_id, name, role, is_owner, created_at, updated_at
                )
                VALUES (:id, :family_id, :user_id, :name, :role, :is_owner, :created_at, :updated_at)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "family_id": family_id_value,
                "user_id": user_id_value,
                "name": "",
                "role": role,
                "is_owner": int(bool(is_owner)),
                "created_at": ts,
                "updated_at": ts,
            },
        )
    else:
        session.execute(
            text(
                """
                INSERT INTO family_members (
                    id, family_id, user_id, role, is_owner, created_at, updated_at
                )
                VALUES (:id, :family_id, :user_id, :role, :is_owner, :created_at, :updated_at)
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "family_id": family_id_value,
                "user_id": user_id_value,
                "role": role,
                "is_owner": int(bool(is_owner)),
                "created_at": ts,
                "updated_at": ts,
            },
        )


def _db_connection() -> sqlite3.Connection:
    from backend.main import db as get_db

    return get_db()


def _normalize_uuid_column(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return str(UUID(bytes=value))
    if value is None:
        return ""
    return str(value)
