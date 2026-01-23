from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db.base import Base, TimestampMixin, UUIDMixin


class Family(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "families"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(512), default=None)

    members: Mapped[List[FamilyMember]] = relationship(
        "FamilyMember", back_populates="family", cascade="all, delete-orphan"
    )
    locations: Mapped[List[Location]] = relationship(
        "Location", back_populates="family", cascade="all, delete-orphan"
    )
    items: Mapped[List[Item]] = relationship(
        "Item", back_populates="family", cascade="all, delete-orphan"
    )
    tags: Mapped[List[Tag]] = relationship(
        "Tag", back_populates="family", cascade="all, delete-orphan"
    )


class User(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(254), nullable=False, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    email_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=None)
    full_name: Mapped[Optional[str]] = mapped_column(String(192), default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")

    family_members: Mapped[List[FamilyMember]] = relationship(
        "FamilyMember", back_populates="user", cascade="all, delete-orphan"
    )
    events: Mapped[List[Event]] = relationship("Event", back_populates="actor")
    attachments: Mapped[List[Attachment]] = relationship("Attachment", back_populates="created_by")
    audit_logs: Mapped[List[AuditLog]] = relationship("AuditLog", back_populates="actor")


class FamilyMember(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "family_members"
    __table_args__ = (UniqueConstraint("family_id", "user_id"),)

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="member")
    is_owner: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    family: Mapped[Family] = relationship("Family", back_populates="members")
    user: Mapped[User] = relationship("User", back_populates="family_members")


class Location(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "locations"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(512), default=None)
    icon: Mapped[Optional[str]] = mapped_column(String(4), default=None)

    family: Mapped[Family] = relationship("Family", back_populates="locations")
    items: Mapped[List[Item]] = relationship("Item", back_populates="location")


class Item(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "items"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=False,
    )
    location_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("locations.id", ondelete="SET NULL"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    icon: Mapped[Optional[str]] = mapped_column(String(4), default=None)
    battery: Mapped[int] = mapped_column(Integer, nullable=False, default=100, server_default="100")
    notes: Mapped[Optional[str]] = mapped_column(Text, default=None)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")

    family: Mapped[Family] = relationship("Family", back_populates="items")
    location: Mapped[Location] = relationship("Location", back_populates="items")
    tags: Mapped[List[ItemTagLink]] = relationship(
        "ItemTagLink", back_populates="item", cascade="all, delete-orphan"
    )

    @property
    def status(self) -> str:
        return "active" if self.is_active else "inactive"

    @property
    def description(self) -> Optional[str]:
        return self.notes


class Tag(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("family_id", "name"),)

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)

    family: Mapped[Family] = relationship("Family", back_populates="tags")
    links: Mapped[List[ItemTagLink]] = relationship(
        "ItemTagLink", back_populates="tag", cascade="all, delete-orphan"
    )


class ItemTagLink(UUIDMixin, Base):
    __tablename__ = "item_tag_links"
    __table_args__ = (UniqueConstraint("item_id", "tag_id"),)

    item_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("items.id", ondelete="CASCADE"),
        nullable=False,
    )
    tag_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("tags.id", ondelete="CASCADE"),
        nullable=False,
    )

    item: Mapped[Item] = relationship("Item", back_populates="tags")
    tag: Mapped[Tag] = relationship("Tag", back_populates="links")


class Event(UUIDMixin, Base):
    __tablename__ = "events"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, default=None)
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    family: Mapped[Family] = relationship("Family")
    actor: Mapped[Optional[User]] = relationship("User", foreign_keys=[actor_user_id], back_populates="events")


class Attachment(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "attachments"

    family_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=False,
    )
    item_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("items.id", ondelete="SET NULL"), nullable=True
    )
    event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"), nullable=True
    )
    filename: Mapped[Optional[str]] = mapped_column(String(256), default=None)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    content_type: Mapped[Optional[str]] = mapped_column(String(128), default=None)
    created_by_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    family: Mapped[Family] = relationship("Family")
    item: Mapped[Optional[Item]] = relationship("Item")
    event: Mapped[Optional[Event]] = relationship("Event")
    created_by: Mapped[Optional[User]] = relationship(
        "User", foreign_keys=[created_by_id], back_populates="attachments"
    )


class AuditLog(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "audit_log"

    family_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        nullable=True,
    )
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    entity: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    details: Mapped[Optional[str]] = mapped_column(Text, default=None)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    target_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    payload_json: Mapped[Optional[str]] = mapped_column(Text, default=None)

    family: Mapped[Family] = relationship("Family")
    actor: Mapped[Optional[User]] = relationship("User", foreign_keys=[actor_user_id], back_populates="audit_logs")
