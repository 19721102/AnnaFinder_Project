from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.v1.deps.auth import require_family_access
from backend.db.session import get_session
from models.entities import AuditLog

router = APIRouter()


class AuditOut(BaseModel):
    id: UUID
    family_id: Optional[UUID]
    actor_user_id: Optional[UUID]
    entity: str
    action: str
    success: bool
    target_type: Optional[str]
    target_id: Optional[UUID]
    ip: Optional[str]
    user_agent: Optional[str]
    payload: Optional[dict[str, Any]]
    details: Optional[str]
    created_at: datetime


class AuditListOut(BaseModel):
    audit: list[AuditOut]
    total: int
    limit: int
    offset: int


def _parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid datetime filter",
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_payload(raw: Optional[str]) -> Optional[dict[str, Any]]:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _split_type(type_filter: str) -> tuple[str, Optional[str]]:
    if "." in type_filter:
        entity, action = type_filter.split(".", 1)
        return entity, action
    return type_filter, None


@router.get("/families/{family_id}/audit", response_model=AuditListOut)
def list_audit(
    family_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
    type_filter: Optional[str] = Query(None, alias="type"),
    actor_user_id: Optional[UUID] = Query(None),
    success: Optional[bool] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> AuditListOut:
    filters: list[Any] = [AuditLog.family_id == family_id]
    if type_filter:
        entity, action = _split_type(type_filter)
        filters.append(AuditLog.entity == entity)
        if action:
            filters.append(AuditLog.action == action)
    if actor_user_id:
        filters.append(AuditLog.actor_user_id == actor_user_id)
    if success is not None:
        filters.append(AuditLog.success == success)
    if date_from:
        dt = _parse_datetime(date_from)
        filters.append(AuditLog.created_at >= dt)
    if date_to:
        dt = _parse_datetime(date_to)
        filters.append(AuditLog.created_at <= dt)
    total = session.execute(
        select(func.count()).select_from(AuditLog).where(*filters)
    ).scalar_one()
    query = (
        select(AuditLog)
        .where(*filters)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = session.execute(query).scalars().all()
    audit_entries = []
    for entry in rows:
        audit_entries.append(
            AuditOut(
                id=entry.id,
                family_id=entry.family_id,
                actor_user_id=entry.actor_user_id,
                entity=entry.entity,
                action=entry.action,
                success=entry.success,
                target_type=entry.target_type,
                target_id=entry.target_id,
                ip=entry.ip,
                user_agent=entry.user_agent,
                payload=_parse_payload(entry.payload_json),
                details=entry.details,
                created_at=entry.created_at,
            )
        )
    return AuditListOut(audit=audit_entries, total=total, limit=limit, offset=offset)
