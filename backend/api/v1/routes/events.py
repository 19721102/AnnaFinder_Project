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
from models.entities import Event, Item

router = APIRouter()


class EventOut(BaseModel):
    id: UUID
    family_id: UUID
    kind: str
    message: str
    payload: dict[str, Any]
    actor_user_id: Optional[UUID]
    timestamp: datetime


class EventsListOut(BaseModel):
    items: list[EventOut]
    total: int
    limit: int
    offset: int


def _parse_datetime(value: str) -> datetime:
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


def _parse_payload(details: str) -> dict[str, Any]:
    if not details:
        return {}
    try:
        return json.loads(details)
    except json.JSONDecodeError:
        return {}


@router.get("/families/{family_id}/events", response_model=EventsListOut)
def list_events(
    family_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
    item_id: Optional[UUID] = Query(None),
    type_filter: Optional[str] = Query(None, alias="type"),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> EventsListOut:
    filters = [Event.family_id == family_id]
    if type_filter:
        filters.append(Event.kind == type_filter)
    if date_from:
        filters.append(Event.ts >= _parse_datetime(date_from))
    if date_to:
        filters.append(Event.ts <= _parse_datetime(date_to))
    if item_id:
        item = session.execute(
            select(Item).where(Item.id == item_id, Item.family_id == family_id)
        ).scalar_one_or_none()
        if not item:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Item not found",
            )
        filters.append(Event.details.contains(f'"item_id":"{item_id}"'))
    total = session.execute(select(func.count()).where(*filters)).scalar_one()
    query = (
        select(Event)
        .where(*filters)
        .order_by(Event.ts.desc())
        .limit(limit)
        .offset(offset)
    )
    rows = session.execute(query).scalars().all()
    items: list[EventOut] = []
    for entry in rows:
        items.append(
            EventOut(
                id=entry.id,
                family_id=entry.family_id,
                kind=entry.kind,
                message=entry.message,
                payload=_parse_payload(entry.details),
                actor_user_id=entry.actor_user_id,
                timestamp=entry.ts,
            )
        )
    return EventsListOut(items=items, total=total, limit=limit, offset=offset)
