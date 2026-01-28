from __future__ import annotations

import json
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
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/csp-report",
    "application/reports+json",
    "text/plain",
}
MAX_BYTES = 64 * 1024
MAX_LENGTH = 512
PREVIEW_CHARS = 200


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


def _normalize_content_type(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


async def _read_body_with_limit(request: Request, max_bytes: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            return b"", False
        chunks.append(chunk)
    return b"".join(chunks), True


def _truncate(text: str, limit: int) -> str:
    return text[:limit]


def _iter_reports(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


@router.post("/csp-report", status_code=204)
async def csp_report(request: Request) -> Response:
    content_type = _normalize_content_type(request.headers.get("content-type"))
    if not content_type or content_type not in ALLOWED_CONTENT_TYPES:
        return Response(status_code=415)

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError:
            length = None
        if length is not None and length > MAX_BYTES:
            return Response(status_code=413)

    body, ok = await _read_body_with_limit(request, MAX_BYTES)
    if not ok:
        return Response(status_code=413)

    request_id = get_request_id(request)
    if content_type == "application/reports+json":
        try:
            payload = json.loads(body.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log_structured(
                logging.WARNING,
                "csp_report",
                payload={},
                path=request.url.path,
                content_type=content_type,
                parse_error=_truncate(str(exc), MAX_LENGTH),
                request_id=request_id,
            )
            return Response(status_code=204)

        reports = _iter_reports(payload)
        csp_logged = 0
        for report in reports:
            if report.get("type") != "csp-violation":
                continue
            body_payload = report.get("body")
            if not isinstance(body_payload, dict):
                continue
            sanitized = _sanitize_payload(body_payload)
            log_structured(
                logging.WARNING,
                "csp_report",
                payload=sanitized,
                path=request.url.path,
                content_type=content_type,
                report_type="csp-violation",
                request_id=request_id,
            )
            csp_logged += 1

        if csp_logged == 0:
            log_structured(
                logging.WARNING,
                "csp_report",
                payload={},
                path=request.url.path,
                content_type=content_type,
                report_count=len(reports),
                request_id=request_id,
            )
        return Response(status_code=204)

    if content_type in {"application/json", "application/csp-report"}:
        try:
            payload = json.loads(body.decode("utf-8", errors="strict"))
            if not isinstance(payload, dict):
                payload = {}
            sanitized = _sanitize_payload(payload)
            log_structured(
                logging.WARNING,
                "csp_report",
                payload=sanitized,
                path=request.url.path,
                content_type=content_type,
                request_id=request_id,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log_structured(
                logging.WARNING,
                "csp_report",
                payload={},
                path=request.url.path,
                content_type=content_type,
                parse_error=_truncate(str(exc), MAX_LENGTH),
                request_id=request_id,
            )
        return Response(status_code=204)

    preview = _truncate(body.decode("utf-8", errors="replace"), PREVIEW_CHARS)
    log_structured(
        logging.WARNING,
        "csp_report",
        payload={},
        path=request.url.path,
        content_type=content_type,
        text_preview=preview,
        request_id=request_id,
    )
    return Response(status_code=204)
