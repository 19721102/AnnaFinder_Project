from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.v1.deps.auth import require_family_access
from backend.db.session import get_session
from backend.services.audit import write_audit
from models.entities import Tag

router = APIRouter()


class TagCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)


class TagOut(BaseModel):
    id: UUID
    family_id: UUID
    name: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


@router.post("/families/{family_id}/tags", response_model=TagOut, status_code=status.HTTP_201_CREATED)
def create_tag(
    family_id: UUID,
    payload: TagCreate,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Tag:
    label = payload.name.strip()
    existing = session.execute(
        select(Tag).where(
            Tag.family_id == family_id, func.lower(Tag.name) == label.lower()
        )
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Tag already exists",
        )
    tag = Tag(family_id=family_id, name=label)
    session.add(tag)
    session.flush()
    write_audit(
        session=session,
        family_id=family_id,
        actor_user_id=UUID(membership["user_id"]),
        event_type="tags.create",
        target_type="tag",
        target_id=tag.id,
        payload={"name": tag.name},
    )
    session.commit()
    session.refresh(tag)
    return tag


@router.get("/families/{family_id}/tags", response_model=list[TagOut])
def list_tags(
    family_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> List[Tag]:
    query = select(Tag).where(Tag.family_id == family_id).order_by(Tag.created_at.desc())
    return session.execute(query).scalars().all()


@router.delete("/families/{family_id}/tags/{tag_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_tag(
    family_id: UUID,
    tag_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> None:
    tag = session.execute(
        select(Tag).where(Tag.id == tag_id, Tag.family_id == family_id)
    ).scalar_one_or_none()
    if not tag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tag not found",
        )
    session.delete(tag)
    write_audit(
        session=session,
        family_id=family_id,
        actor_user_id=UUID(membership["user_id"]),
        event_type="tags.delete",
        target_type="tag",
        target_id=tag.id,
        payload={"name": tag.name},
    )
    session.commit()
