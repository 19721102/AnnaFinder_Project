from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Request, Response

from backend.observability import get_request_id, log_structured

router = APIRouter()

ALLOWED_KEYS = {
    "document-uri",
    "blocked-uri",
    "violated-directive",
    "effective-directive",
    "disposition",
    "original-policy",
    "referrer",
    "status-code",
    "source-file",
    "line-number",
    "column-number",
}
MAX_LENGTH = 512


def _sanitize_value(value: Any) -> str:
    if isinstance(value, str):
        value = value.split("?", 1)[0]
        return value[:MAX_LENGTH]
    return str(value)[:MAX_LENGTH]


def _sanitize_payload(payload: dict[str, Any]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key, value in payload.items():
        key_lower = key.lower()
        if key_lower not in ALLOWED_KEYS:
            continue
        sanitized[key_lower] = _sanitize_value(value)
    return sanitized


@router.post("/csp-report", status_code=204)
async def csp_report(request: Request) -> Response:
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            payload = {}
    except ValueError:
        payload = {}
    sanitized = _sanitize_payload(payload)
    log_structured(
        logging.WARNING,
        "csp_report",
        payload=sanitized,
        path=request.url.path,
        request_id=get_request_id(request),
    )
    return Response(status_code=204)
