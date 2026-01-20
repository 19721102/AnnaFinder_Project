from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError

ERROR_CODES = {
    "validation": "VALIDATION_ERROR",
    "http": "HTTP_ERROR",
    "internal": "INTERNAL_ERROR",
}


def make_error_payload(code: str, message: str, details: Optional[Any] = None) -> Dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details,
        }
    }


def format_validation_details(exc: RequestValidationError) -> List[Dict[str, Any]]:
    formatted: List[Dict[str, Any]] = []
    for err in exc.errors():
        formatted.append(
            {
                "loc": err.get("loc"),
                "msg": err.get("msg"),
                "type": err.get("type"),
            }
        )
    return formatted


def http_error_payload(exc: HTTPException) -> Dict[str, Any]:
    message = exc.detail if isinstance(exc.detail, str) else "HTTP error"
    return make_error_payload(
        ERROR_CODES["http"],
        message,
        {"status_code": exc.status_code},
    )
