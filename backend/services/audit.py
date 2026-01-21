from __future__ import annotations

import json
from typing import Any, Optional
from uuid import UUID

from fastapi import Request
from sqlalchemy.orm import Session

from backend.db.session import SessionLocal
from models.entities import AuditLog


def _sanitize_payload(payload: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not payload:
        return {}
    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        lowered = key.lower()
        if "password" in lowered or "token" in lowered:
            continue
        sanitized[key] = value
    return sanitized


def _extract_request_context(request: Optional[Request]) -> tuple[Optional[str], Optional[str]]:
    if not request:
        return None, None
    client = request.client
    ip = client.host if client else None
    user_agent = request.headers.get("user-agent")
    return ip, user_agent


def write_audit(
    *,
    session: Optional[Session] = None,
    family_id: Optional[UUID] = None,
    actor_user_id: Optional[UUID] = None,
    event_type: str,
    success: bool = True,
    target_type: Optional[str] = None,
    target_id: Optional[UUID] = None,
    request: Optional[Request] = None,
    payload: Optional[dict[str, Any]] = None,
    details: Optional[str] = None,
) -> AuditLog:
    close_session = False
    if session is None:
        session = SessionLocal()
        close_session = True
    entity, action = _split_event_type(event_type)
    sanitized_payload = _sanitize_payload(payload)
    payload_json = (
        json.dumps(sanitized_payload, separators=(",", ":"), default=str)
        if sanitized_payload
        else None
    )
    ip, user_agent = _extract_request_context(request)
    entry = AuditLog(
        family_id=family_id,
        actor_user_id=actor_user_id,
        entity=entity,
        action=action,
        success=success,
        target_type=target_type,
        target_id=target_id,
        ip=ip,
        user_agent=user_agent,
        payload_json=payload_json,
        details=details or event_type,
    )
    session.add(entry)
    if close_session:
        session.commit()
        session.close()
    return entry


def _split_event_type(event_type: str) -> tuple[str, str]:
    if "." in event_type:
        primary, remainder = event_type.split(".", 1)
        return primary, remainder
    return event_type, event_type
