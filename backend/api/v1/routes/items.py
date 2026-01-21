from __future__ import annotations

from datetime import datetime
from typing import Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.v1.deps.auth import require_family_access
from backend.db.session import get_session
from backend.services.events import emit_event
from models.entities import Item, Location

router = APIRouter()


class ItemBase(BaseModel):
    description: Optional[str] = Field(None, max_length=512)
    location_id: Optional[UUID] = None


class ItemCreate(ItemBase):
    name: str = Field(..., min_length=1, max_length=128)


class ItemUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    location_id: Optional[UUID] = None


class ItemOut(BaseModel):
    id: UUID
    family_id: UUID
    name: str
    description: Optional[str]
    location_id: Optional[UUID]
    status: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ItemListOut(BaseModel):
    items: list[ItemOut]
    total: int
    limit: int
    offset: int


def _ensure_location_in_family(session: Session, family_id: UUID, location_id: UUID) -> Location:
    location = session.execute(
        select(Location).where(Location.id == location_id, Location.family_id == family_id)
    ).scalar_one_or_none()
    if not location:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Family not found or access denied",
        )
    return location


def _build_item_filters(
    family_id: UUID,
    location_id: Optional[UUID],
    q: Optional[str],
    status_value: Optional[str],
) -> list[Any]:
    filters = [Item.family_id == family_id]
    if location_id:
        filters.append(Item.location_id == location_id)
    if q:
        filters.append(func.lower(Item.name).contains(q.lower()))
    if status_value:
        desired = status_value.lower() == "active"
        filters.append(Item.is_active == desired)
    return filters


@router.post("/families/{family_id}/items", response_model=ItemOut, status_code=status.HTTP_201_CREATED)
def create_item(
    family_id: UUID,
    payload: ItemCreate,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Item:
    if payload.location_id:
        _ensure_location_in_family(session, family_id, payload.location_id)
    item = Item(
        family_id=family_id,
        name=payload.name,
        notes=payload.description,
        location_id=payload.location_id,
    )
    session.add(item)
    session.flush()
    actor_id = UUID(membership["user_id"])
    emit_event(
        session,
        family_id,
        "item.created",
        "Item created",
        actor_user_id=actor_id,
        payload={
            "item_id": str(item.id),
            "name": item.name,
            "location_id": str(item.location_id) if item.location_id else None,
        },
    )
    session.commit()
    session.refresh(item)
    return item


@router.get("/families/{family_id}/items", response_model=ItemListOut)
def list_items(
    family_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    location_id: Optional[UUID] = Query(None),
    q: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> ItemListOut:
    filters = _build_item_filters(family_id, location_id, q, status)
    base_query = select(Item).where(*filters).order_by(Item.created_at.desc())
    total = session.execute(
        select(func.count()).select_from(Item).where(*filters)
    ).scalar_one()
    rows = session.execute(base_query.limit(limit).offset(offset)).scalars().all()
    return ItemListOut(
        items=rows,
        total=total,
        limit=limit,
        offset=offset,
    )


def _get_family_item(
    session: Session, family_id: UUID, item_id: UUID
) -> Optional[Item]:
    return session.execute(
        select(Item).where(Item.id == item_id, Item.family_id == family_id)
    ).scalar_one_or_none()


@router.get("/families/{family_id}/items/{item_id}", response_model=ItemOut)
def get_item(
    family_id: UUID,
    item_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Item:
    item = _get_family_item(session, family_id, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    return item


@router.patch("/families/{family_id}/items/{item_id}", response_model=ItemOut)
def update_item(
    family_id: UUID,
    item_id: UUID,
    payload: ItemUpdate,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Item:
    item = _get_family_item(session, family_id, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    previous_name = item.name
    previous_description = item.description
    previous_location = item.location_id
    if payload.location_id:
        _ensure_location_in_family(session, family_id, payload.location_id)
        item.location_id = payload.location_id
    if payload.name is not None:
        item.name = payload.name
    if payload.description is not None:
        item.notes = payload.description
    session.add(item)
    session.flush()
    changed_fields: list[str] = []
    if payload.name is not None and payload.name != previous_name:
        changed_fields.append("name")
    if payload.description is not None and payload.description != previous_description:
        changed_fields.append("description")
    moved = (
        payload.location_id is not None
        and payload.location_id != previous_location
    )
    if (
        payload.location_id is not None
        and payload.location_id != previous_location
        and "location_id" not in changed_fields
    ):
        changed_fields.append("location_id")
    actor_id = UUID(membership["user_id"])
    if changed_fields:
        emit_event(
            session,
            family_id,
            "item.updated",
            "Item updated",
            actor_user_id=actor_id,
            payload={
                "item_id": str(item.id),
                "fields_changed": list(changed_fields),
            },
        )
    if moved:
        emit_event(
            session,
            family_id,
            "item.moved",
            "Item moved",
            actor_user_id=actor_id,
            payload={
                "item_id": str(item.id),
                "from_location_id": str(previous_location) if previous_location else None,
                "to_location_id": str(item.location_id) if item.location_id else None,
                "fields_changed": list(changed_fields) or ["location_id"],
            },
        )
    session.commit()
    session.refresh(item)
    return item


@router.delete("/families/{family_id}/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(
    family_id: UUID,
    item_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Response:
    item = _get_family_item(session, family_id, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    session.delete(item)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
