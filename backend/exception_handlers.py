from __future__ import annotations

import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.errors import ERROR_CODES, format_validation_details, http_error_payload, make_error_payload

logger = logging.getLogger("annafinder")


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)  # type: ignore[misc]
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = format_validation_details(exc)
        payload = make_error_payload(ERROR_CODES["validation"], "Invalid request", details)
        return JSONResponse(status_code=422, content=payload)

    @app.exception_handler(HTTPException)  # type: ignore[misc]
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        payload = http_error_payload(exc)
        detail = payload["error"]["message"]
        payload_with_detail = {**payload, "detail": detail}
        return JSONResponse(status_code=exc.status_code, content=payload_with_detail)

    @app.exception_handler(Exception)  # type: ignore[misc]
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unexpected error during request handling", exc_info=exc)
        payload = make_error_payload(ERROR_CODES["internal"], "Unexpected error", None)
        return JSONResponse(status_code=500, content=payload)
