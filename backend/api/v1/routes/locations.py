from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.api.v1.deps.auth import require_family_access
from backend.db.session import get_session
from models.entities import Location

router = APIRouter()


class LocationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    icon: Optional[str] = Field(None, min_length=1, max_length=4)


class LocationCreate(LocationBase):
    pass


class LocationUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    icon: Optional[str] = Field(None, min_length=1, max_length=4)


class LocationOut(LocationBase):
    id: UUID
    family_id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class LocationListOut(BaseModel):
    items: list[LocationOut]
    total: int
    limit: int
    offset: int


def _get_family_locations_query(family_id: UUID):
    return select(Location).where(Location.family_id == family_id).order_by(Location.created_at.desc())


@router.post(
    "/families/{family_id}/locations",
    response_model=LocationOut,
    status_code=status.HTTP_201_CREATED,
)
def create_location(
    family_id: UUID,
    payload: LocationCreate,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Location:
    location = Location(
        family_id=family_id,
        name=payload.name,
        description=payload.description,
        icon=payload.icon,
    )
    session.add(location)
    session.commit()
    session.refresh(location)
    return location


@router.get("/families/{family_id}/locations", response_model=LocationListOut)
def list_locations(
    family_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> LocationListOut:
    query = _get_family_locations_query(family_id)
    total = session.execute(select(func.count()).select_from(Location).where(Location.family_id == family_id)).scalar_one()
    rows = session.execute(query.limit(limit).offset(offset)).scalars().all()
    return LocationListOut(items=rows, total=total, limit=limit, offset=offset)


def _get_location_for_family(
    session: Session, family_id: UUID, location_id: UUID
) -> Optional[Location]:
    result = session.execute(
        select(Location).where(Location.id == location_id, Location.family_id == family_id)
    ).scalar_one_or_none()
    return result


@router.get("/families/{family_id}/locations/{location_id}", response_model=LocationOut)
def get_location(
    family_id: UUID,
    location_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Location:
    location = _get_location_for_family(session, family_id, location_id)
    if not location:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Location not found")
    return location


@router.patch("/families/{family_id}/locations/{location_id}", response_model=LocationOut)
def update_location(
    family_id: UUID,
    location_id: UUID,
    payload: LocationUpdate,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Location:
    location = _get_location_for_family(session, family_id, location_id)
    if not location:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Location not found")
    if payload.name is not None:
        location.name = payload.name
    if payload.description is not None:
        location.description = payload.description
    if payload.icon is not None:
        location.icon = payload.icon
    session.add(location)
    session.commit()
    session.refresh(location)
    return location


@router.delete("/families/{family_id}/locations/{location_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_location(
    family_id: UUID,
    location_id: UUID,
    membership=Depends(require_family_access),
    session: Session = Depends(get_session),
) -> Response:
    location = _get_location_for_family(session, family_id, location_id)
    if not location:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Location not found")
    session.delete(location)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
