from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

HEADER_VALUES = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "X-Frame-Options": "SAMEORIGIN",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}
HSTS_VALUE = "max-age=31536000; includeSubDomains"


def _is_https_request(request: Request) -> bool:
    scheme = request.url.scheme
    if scheme == "https":
        return True
    header = request.headers.get("x-forwarded-proto", "")
    return header.split(",")[0].strip().lower() == "https"


def add_security_headers(response: Response, request: Request, app_env: str) -> None:
    for name, value in HEADER_VALUES.items():
        response.headers.setdefault(name, value)
    if app_env == "prod" and _is_https_request(request):
        response.headers.setdefault("Strict-Transport-Security", HSTS_VALUE)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, app_env: str) -> None:
        super().__init__(app)
        self.app_env = app_env

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        env = getattr(request.app.state, "app_env", self.app_env)
        add_security_headers(response, request, env)
        return response
