import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from security_log_writer import write_security_log

EVENT_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "password",
    "secret",
    "x-csrf-token",
}
def iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sanitize_str(value: Optional[str], max_len: int = 256) -> str:
    if value is None:
        return ""
    s = str(value).replace("\r", " ").replace("\n", " ").strip()
    return s[:max_len]


def safe_hash(value: Optional[str]) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scrub_string_value(key: str, value: str) -> str:
    lower_key = key.lower()
    if any(term in lower_key for term in EVENT_SENSITIVE_KEYS):
        return "REDACTED"
    if "email" in lower_key:
        return safe_hash(value)
    return sanitize_str(value)


def _scrub_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    sanitized: Dict[str, Any] = {}
    for k, v in ctx.items():
        if isinstance(v, str):
            sanitized[k] = _scrub_string_value(k, v)
        else:
            sanitized[k] = v
    return sanitized


def build_actor(ctx: Dict[str, Any]) -> Dict[str, str]:
    return {
        "user_id": sanitize_str(ctx.get("user_id")),
        "household_id": sanitize_str(ctx.get("household_id")),
        "session_hash": sanitize_str(ctx.get("session_hash")),
    }


def emit_event(event: Dict[str, Any]) -> None:
    meta_raw = event.get("meta", {}) or {}
    meta: Dict[str, Any] = {}
    for k, v in meta_raw.items():
        key = sanitize_str(str(k))
        if isinstance(v, str):
            meta[key] = _scrub_string_value(key, v)
        else:
            meta[key] = v
    payload = {
        "ts": iso_utc(),
        "event": sanitize_str(event.get("event")),
        "severity": sanitize_str(event.get("severity", "INFO")),
        "request_id": sanitize_str(event.get("request_id")),
        "actor": _scrub_context(event.get("actor", {})),
        "source": _scrub_context(event.get("source", {})),
        "target": event.get("target", {}),
        "outcome": sanitize_str(event.get("outcome", "SUCCESS")),
        "meta": meta,
    }
    line = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    write_security_log(line)
