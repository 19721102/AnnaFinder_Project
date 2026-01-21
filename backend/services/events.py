from __future__ import annotations

import json
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from models.entities import Event


def emit_event(
    session: Session,
    family_id: UUID,
    kind: str,
    message: str,
    *,
    actor_user_id: Optional[UUID] = None,
    payload: Optional[dict[str, Any]] = None,
) -> Event:
    details = json.dumps(payload or {}, separators=(",", ":"), default=str)
    event = Event(
        family_id=family_id,
        kind=kind,
        message=message,
        details=details,
        actor_user_id=actor_user_id,
    )
    session.add(event)
    return event
