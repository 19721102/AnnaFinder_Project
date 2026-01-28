import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from backend.observability import get_request_id, log_structured, sanitize_payload

router = APIRouter()


class ErrorReportPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    message: str
    kind: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    stack: Optional[str] = None


@router.post("/error-report", status_code=202)
def report_error(payload: ErrorReportPayload, request: Request) -> Dict[str, str]:
    data = sanitize_payload(payload.model_dump(exclude_none=True))
    log_structured(
        logging.ERROR,
        "error_report",
        message="error report received",
        path=request.url.path,
        payload=data,
    )
    return {"status": "accepted", "request_id": get_request_id(request)}
