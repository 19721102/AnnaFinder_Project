import contextvars
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import Request

from backend.security_events import sanitize_str

REQUEST_ID_CTX: contextvars.ContextVar[str] = contextvars.ContextVar("annafinder_request_id", default="")

SENSITIVE_FIELDS = {"password", "token"}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for key, value in payload.items():
        if key.lower() in SENSITIVE_FIELDS:
            sanitized[key] = "<redacted>"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_payload(value)
        else:
            sanitized[key] = value
    return sanitized


class StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": iso_utc(now_utc()),
            "level": record.levelname,
            "logger": record.name,
        }
        structured = getattr(record, "structured", None)
        if structured:
            entry.update(structured)
        else:
            entry["event"] = record.getMessage()
        return json.dumps(entry, ensure_ascii=True)


def set_active_request_id(value: str) -> contextvars.Token[str]:
    return REQUEST_ID_CTX.set(value)


def reset_active_request_id(token: contextvars.Token[str]) -> None:
    REQUEST_ID_CTX.reset(token)


def get_active_request_id() -> str:
    return REQUEST_ID_CTX.get() or ""


def get_request_id(request: Request) -> str:
    rid = getattr(request.state, "request_id", "") or request.headers.get("X-Request-Id", "")
    return sanitize_str(rid, 64)


def log_structured(level: int, event: str, **fields: Any) -> None:
    logger = logging.getLogger("annafinder")
    structured = {
        "event": event,
        **fields,
    }
    logger.log(level, "", extra={"structured": structured})
