from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class TimestampedSchema(BaseModel):
    created_at: datetime
    updated_at: datetime


class UserSchema(TimestampedSchema):
    id: UUID
    email: str
    full_name: Optional[str]
    is_active: bool = Field(..., description="Flag indicating if the user can log in")


class FamilySchema(TimestampedSchema):
    id: UUID
    name: str
    description: Optional[str]


class FamilyMemberSchema(TimestampedSchema):
    id: UUID
    family_id: UUID
    user_id: UUID
    role: str
    is_owner: bool


class LocationSchema(TimestampedSchema):
    id: UUID
    family_id: UUID
    name: str
    description: Optional[str]
    icon: Optional[str]


class ItemSchema(TimestampedSchema):
    id: UUID
    family_id: UUID
    location_id: Optional[UUID]
    name: str
    icon: Optional[str]
    notes: Optional[str]
    status: Optional[str]
    is_active: bool


class TagSchema(TimestampedSchema):
    id: UUID
    family_id: UUID
    name: str


class EventSchema(BaseModel):
    id: UUID
    family_id: UUID
    actor_user_id: Optional[UUID]
    type: str
    payload_json: Optional[str]
    created_at: datetime


class AttachmentSchema(TimestampedSchema):
    id: UUID
    family_id: UUID
    item_id: Optional[UUID]
    filename: Optional[str]
    content_type: Optional[str]
    size_bytes: Optional[int]
    storage_key: Optional[str]


class AuditLogSchema(TimestampedSchema):
    id: UUID
    family_id: Optional[UUID]
    actor_user_id: Optional[UUID]
    action: str
    target_type: Optional[str]
    target_id: Optional[UUID]
    ip: Optional[str]
    user_agent: Optional[str]
    meta_json: Optional[str]
