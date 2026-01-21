from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.v1.deps.auth import require_family_access
from backend.db.session import get_session
from backend.services.events import emit_event
from models.entities import Item, ItemTagLink, Tag

router = APIRouter()


def _get_item(session: Session, family_id: UUID, item_id: UUID) -> Item | None:
    return session.execute(
        select(Item).where(Item.id == item_id, Item.family_id == family_id)
    ).scalar_one_or_none()


def _get_tag(session: Session, family_id: UUID, tag_id: UUID) -> Tag | None:
    return session.execute(
        select(Tag).where(Tag.id == tag_id, Tag.family_id == family_id)
    ).scalar_one_or_none()


@router.post(
    "/families/{family_id}/items/{item_id}/tags/{tag_id}", status_code=status.HTTP_200_OK
)
def link_tag(
    family_id: UUID,
    item_id: UUID,
    tag_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> dict[str, bool]:
    item = _get_item(session, family_id, item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")
    tag = _get_tag(session, family_id, tag_id)
    if not tag:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tag not found")
    existing = session.execute(
        select(ItemTagLink).where(
            ItemTagLink.item_id == item.id, ItemTagLink.tag_id == tag.id
        )
    ).scalar_one_or_none()
    if existing:
        return {"ok": True}
    link = ItemTagLink(item_id=item.id, tag_id=tag.id)
    session.add(link)
    session.flush()
    emit_event(
        session,
        family_id,
        "tag.linked",
        "Tag linked to item",
        actor_user_id=UUID(membership["user_id"]),
        payload={"item_id": str(item.id), "tag_id": str(tag.id)},
    )
    session.commit()
    return {"ok": True}


@router.delete(
    "/families/{family_id}/items/{item_id}/tags/{tag_id}", status_code=status.HTTP_204_NO_CONTENT
)
def unlink_tag(
    family_id: UUID,
    item_id: UUID,
    tag_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Response:
    link = session.execute(
        select(ItemTagLink)
        .join(Tag)
        .where(
            ItemTagLink.item_id == item_id,
            ItemTagLink.tag_id == tag_id,
            Tag.family_id == family_id,
        )
    ).scalar_one_or_none()
    if not link:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    session.delete(link)
    session.flush()
    emit_event(
        session,
        family_id,
        "tag.unlinked",
        "Tag unlinked from item",
        actor_user_id=UUID(membership["user_id"]),
        payload={"item_id": str(item_id), "tag_id": str(tag_id)},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
