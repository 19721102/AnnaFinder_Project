import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from time import monotonic
from collections import deque, defaultdict
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Deque, List, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, PlainTextResponse
from pydantic import BaseModel, Field
from email_service import enqueue_email, render_email_body, send_pending_emails
from permissions import (
    PERM_DATA_DELETE,
    PERM_DATA_EXPORT,
    PERM_FEEDBACK_SUBMIT,
    PERM_HOUSEHOLD_PROFILE_UPDATE,
    PERM_INVITE_ACCEPT,
    PERM_INVITE_CREATE,
    PERM_INVITE_REVOKE,
    PERM_ITEM_CREATE,
    PERM_ITEM_UPDATE,
    PERM_MEMBER_VIEW,
    PERM_MEMBER_REMOVE,
    PERM_MEMBER_ROLE_CHANGE,
    ROLE_MEMBER,
    ROLE_OWNER,
    ROLE_VIEWER,
    require_permission as require_permission_core,
)
from jwt import PyJWTError

from backend.errors import ERROR_CODES, make_error_payload
from backend.security.passwords import hash_password, verify_password
from backend.db.migrations import alembic_upgrade_head
from backend.db.seed import seed_demo_data
from backend.db.session import DATABASE_URL, SessionLocal
from security_events import build_actor, emit_event, safe_hash, sanitize_str
from backend.security.jwt import decode_token
from backend.api.v1.router import api_v1_router
from backend.exception_handlers import register_exception_handlers
from backend.observability import (
    StructuredFormatter,
    get_request_id,
    log_structured,
    reset_active_request_id,
    set_active_request_id,
)
from backend.security_headers import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    log_structured(logging.INFO, "startup", message="AnnaFinder backend initializing", env=ANNAFINDER_ENV)
    validate_email_settings()
    init_db()
    if APP_ENV == "dev" and SEED_ON_STARTUP:
        logger.info("SEED_ON_STARTUP enabled; seeding demo data")
        seed_if_empty()
    try:
        yield
    finally:
        log_structured(logging.INFO, "shutdown", message="AnnaFinder backend closing", env=ANNAFINDER_ENV)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ANNAFINDER_ENV = os.getenv("ANNAFINDER_ENV", "dev").strip().lower()
APP_ENV = os.getenv("APP_ENV", ANNAFINDER_ENV).strip().lower()
SERVICE_VERSION = os.getenv("APP_VERSION") or "dev"
SEED_ON_STARTUP = os.getenv("SEED_ON_STARTUP", "0").strip() == "1"
TEST_DB_PATH = os.path.join(BASE_DIR, "annafinder_test.db")
DB_PATH = TEST_DB_PATH if ANNAFINDER_ENV == "test" else os.path.join(BASE_DIR, "annafinder.db")
APP_VERSION = "0.1.0"
START_TIME = time.monotonic()
BASE_URL = os.getenv("ANNAFINDER_BASE_URL", "http://localhost:3000").strip().rstrip("/")
METRICS_TOKEN = os.getenv("METRICS_TOKEN", "").strip()


app = FastAPI(
    title="AnnaFinder Backend",
    version="1.0.1",
    lifespan=lifespan,
    openapi_tags=[
        {"name": "meta", "description": "Metadata and discovery endpoints"},
        {"name": "auth", "description": "Authentication and session control"},
        {"name": "audit", "description": "Audit and observability endpoints"},
        {"name": "events", "description": "Event and timeline management"},
        {"name": "families", "description": "Family management flows"},
        {"name": "items", "description": "Item management and tagging"},
        {"name": "locations", "description": "Location planning and CRUD"},
        {"name": "observability", "description": "Logging and error reporting helpers"},
        {"name": "tags", "description": "Tag management for families/items"},
        {"name": "item-tags", "description": "Item-tag linking operations"},
    ],
)

app.add_middleware(SecurityHeadersMiddleware, app_env=APP_ENV)
app.state.app_env = APP_ENV

SESSION_COOKIE_BASE_NAME = "anna_session"
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ALLOWED_COLUMN_TYPES = frozenset(
    {"TEXT", "INTEGER", "REAL", "BLOB", "NUMERIC", "BOOLEAN", "TIMESTAMP", "DATETIME", "DATE"}
)


def validate_identifier(name: str) -> str:
    if not name or not IDENTIFIER_PATTERN.fullmatch(name):
        raise ValueError(f"Invalid SQL identifier: {name!r}")
    return name


def validate_sqlite_col_type(col_type: str) -> str:
    norm = (col_type or "").strip().upper()
    if norm not in ALLOWED_COLUMN_TYPES:
        raise ValueError("Invalid column type")
    return norm
CSRF_SAFE_PATHS = {
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/api/v1/auth/register",
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/__csp_report",
    "/api/v1/error-report",
}
CSRF_SAFE_PREFIXES = set()
CSRF_DEV_PATHS = {"/__test__/reset", "/__test__/emails/flush"}
MAX_CSP_REPORT_BYTES = 64 * 1024
CSP_REPORT_RATE_LIMIT = 30
CSP_REPORT_WINDOW = 60
_csp_rate_limits: Dict[str, Deque[float]] = defaultdict(deque)
AUTH_STATE_PATHS = {
    "/auth/login",
    "/auth/register",
    "/auth/password/reset/request",
    "/auth/password/reset/confirm",
    "/auth/verify-email/resend",
    "/api/v1/error-report",
}

DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
DEV_EXTRA_ALLOWED_ORIGINS = [
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]

DEFAULT_ALLOWED_HOSTS = ["localhost", "127.0.0.1", "testserver", "backend"]
KNOWN_TABLES = frozenset(
    {
        "items",
        "events",
        "routines",
        "family_members",
        "users",
        "households",
        "household_members",
        "sessions",
        "password_reset_tokens",
        "email_verifications",
        "email_outbox",
        "feedback",
        "household_invites",
    }
)


def _build_allowed_origins() -> List[str]:
    env_origins = [
        origin.strip()
        for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    ]
    origins: List[str]
    if env_origins:
        if any(origin == "*" for origin in env_origins):
            raise ValueError("ALLOWED_ORIGINS cannot contain '*' when allow_credentials=True")
        origins = env_origins
    else:
        origins = list(DEFAULT_ALLOWED_ORIGINS)
        if ANNAFINDER_ENV in ("test", "dev"):
            origins.extend(DEV_EXTRA_ALLOWED_ORIGINS)
    frontend_port = os.getenv("FRONTEND_PORT", "").strip()
    if frontend_port.isdigit():
        origins.append(f"http://localhost:{frontend_port}")
        origins.append(f"http://127.0.0.1:{frontend_port}")
    return list(dict.fromkeys(origins))


def _build_allowed_hosts() -> List[str]:
    env_hosts = [
        host.strip()
        for host in os.getenv("ALLOWED_HOSTS", "").split(",")
        if host.strip()
    ]
    if env_hosts:
        hosts = list(dict.fromkeys(env_hosts))
    elif ANNAFINDER_ENV == "prod":
        raise RuntimeError("ALLOWED_HOSTS must be defined when ANNAFINDER_ENV=prod")
    else:
        hosts = list(DEFAULT_ALLOWED_HOSTS)
    if BASE_URL:
        try:
            from urllib.parse import urlparse

            parsed = urlparse(BASE_URL)
            if parsed.hostname:
                hosts.append(parsed.hostname)
        except Exception:
            pass
    return list(dict.fromkeys(hosts))


def get_session_cookie_name() -> str:
    if ANNAFINDER_ENV == "prod":
        return f"__Host-{SESSION_COOKIE_BASE_NAME}"
    return SESSION_COOKIE_BASE_NAME


CORS_ALLOWED_ORIGINS = _build_allowed_origins()
TRUSTED_HOSTS = _build_allowed_hosts()

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=TRUSTED_HOSTS,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Request-Id"],
    expose_headers=["Content-Disposition", "X-Request-Id"],
)

logger = logging.getLogger("annafinder")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

register_exception_handlers(app)
app.include_router(api_v1_router, prefix="/api/v1", tags=["v1"])

_original_openapi = app.openapi

def _custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    schema = _original_openapi()
    openapi_path = schema.get("paths", {}).get("/openapi.json", {}).get("get")
    if openapi_path is not None:
        openapi_path.setdefault("summary", "OpenAPI contract")
        openapi_path.setdefault(
            "description",
            "JSON manifest that describes every route, schema, and tag for the AnnaFinder API.",
        )
        responses = openapi_path.setdefault("responses", {})
        responses.setdefault("200", {"description": "OpenAPI schema document"})
    schema.setdefault("tags", [])
    app.openapi_schema = schema
    return schema

app.openapi = _custom_openapi

_metrics_lock = threading.Lock()
_metrics = {
    "requests_total": 0,
    "status_2xx": 0,
    "status_4xx": 0,
    "status_5xx": 0,
    "latency_ms_sum": 0.0,
}

_delete_tokens_lock = threading.Lock()
_delete_tokens: Dict[str, Tuple[float, str]] = {}

RETENTION_EVENTS_DAYS = 365
RETENTION_LOGS_DAYS = 30
SESSION_TTL_SECONDS = 60 * 60 * 12
CSRF_COOKIE_NAME = "anna_csrf"
SESSION_IDLE_TIMEOUT_SECONDS = int(os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "1800"))
SESSION_ABSOLUTE_TIMEOUT_SECONDS = int(os.getenv("SESSION_ABSOLUTE_TIMEOUT_SECONDS", "28800"))
LOGIN_RATE_WINDOW_SECONDS = 300
LOGIN_RATE_MAX_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = int(os.getenv("LOCKOUT_WINDOW_SECONDS", "600"))
LOCKOUT_THRESHOLD = int(os.getenv("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_DURATION_SECONDS = int(os.getenv("LOCKOUT_DURATION_SECONDS", "900"))
RESET_TOKEN_TTL_SECONDS = int(os.getenv("RESET_TOKEN_TTL_SECONDS", "1800"))
RESET_RATE_WINDOW_SECONDS = int(os.getenv("RESET_RATE_WINDOW_SECONDS", "600"))
RESET_RATE_MAX_ATTEMPTS = int(os.getenv("RESET_RATE_MAX_ATTEMPTS", "5"))
INVITE_RATE_WINDOW_SECONDS = int(os.getenv("INVITE_RATE_WINDOW_SECONDS", "900"))
INVITE_RATE_MAX_ATTEMPTS = int(os.getenv("INVITE_RATE_MAX_ATTEMPTS", "5"))
REGISTER_RATE_WINDOW_SECONDS = int(os.getenv("REGISTER_RATE_WINDOW_SECONDS", "900"))
REGISTER_RATE_MAX_ATTEMPTS = int(os.getenv("REGISTER_RATE_MAX_ATTEMPTS", "5"))
VERIFY_RATE_WINDOW_SECONDS = int(os.getenv("VERIFY_RATE_WINDOW_SECONDS", "900"))
VERIFY_RATE_MAX_ATTEMPTS = int(os.getenv("VERIFY_RATE_MAX_ATTEMPTS", "5"))
EMAIL_VERIFY_TTL_SECONDS = int(os.getenv("EMAIL_VERIFY_TTL_SECONDS", "86400"))
HOUSEHOLD_NAME_MAX_LEN = 80


def require_permission(session: Dict[str, Any], permission: str, request: Request) -> str:
    if permission == PERM_INVITE_CREATE and ANNAFINDER_ENV == "test":
        return require_permission_core(
            session, permission, request, get_member_role, build_security_context
        )
    if permission in SENSITIVE_EMAIL_PERMISSIONS and not is_email_verified(session):
        ctx = build_security_context(request, session)
        emit_event(
            {
                **ctx,
                "event": "AUTHZ_DENY",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": sanitize_str(request.url.path)},
                "meta": {"reason": "email_unverified", "permission": sanitize_str(permission)},
            }
        )
        raise HTTPException(status_code=403, detail="Email verification required")
    return require_permission_core(
        session, permission, request, get_member_role, build_security_context
    )


_login_rate_lock = threading.Lock()
_login_rate: Dict[str, Tuple[float, int]] = {}
_lockout_lock = threading.Lock()
_login_failures: Dict[str, Tuple[float, int]] = {}
_lockout_until: Dict[str, float] = {}
_reset_rate_lock = threading.Lock()
_reset_rate: Dict[str, Tuple[float, int]] = {}
_invite_rate_lock = threading.Lock()
_invite_rate: Dict[str, Tuple[float, int]] = {}
_register_rate_lock = threading.Lock()
_register_rate: Dict[str, Tuple[float, int]] = {}
_verify_rate_lock = threading.Lock()
_verify_rate: Dict[str, Tuple[float, int]] = {}


class AddItemInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    icon: str = Field("ÐY?", min_length=1, max_length=4)
    location: str = Field(..., min_length=1, max_length=64)
    battery: int = Field(100, ge=0, le=100)
    notes: str = Field("", max_length=200)


class EditItemInput(BaseModel):
    item_id: str
    name: Optional[str] = Field(None, min_length=1, max_length=64)
    icon: Optional[str] = Field(None, min_length=1, max_length=4)
    location: Optional[str] = Field(None, min_length=1, max_length=64)
    battery: Optional[int] = Field(None, ge=0, le=100)
    notes: Optional[str] = Field(None, max_length=200)


class MoveItemInput(BaseModel):
    item_id: str
    to_location: str = Field(..., min_length=1, max_length=64)


class DeleteConfirmInput(BaseModel):
    delete_token: str
    confirm_text: str


class LoginInput(BaseModel):
    email: str = Field(..., min_length=3, max_length=200)
    password: str = Field(..., min_length=6, max_length=200)


class RegisterInput(BaseModel):
    email: str = Field(..., min_length=3, max_length=200)
    password: str = Field(..., min_length=8, max_length=200)
    household_name: Optional[str] = Field(None, max_length=HOUSEHOLD_NAME_MAX_LEN)


class ResetRequestInput(BaseModel):
    email: str = Field(..., min_length=3, max_length=200)


class ResetConfirmInput(BaseModel):
    token: str = Field(..., min_length=10, max_length=256)
    new_password: str = Field(..., min_length=8, max_length=200)


class VerifyResendInput(BaseModel):
    email: Optional[str] = Field(None, min_length=3, max_length=200)


class FeedbackInput(BaseModel):
    page: str = Field(..., min_length=1, max_length=120)
    rating: Optional[int] = Field(None, ge=1, le=5)
    message: str = Field(..., min_length=1, max_length=1000)


class InviteCreateInput(BaseModel):
    role: str = Field(..., min_length=3, max_length=10)
    email: str = Field(..., min_length=3, max_length=200)


class InviteAcceptInput(BaseModel):
    token: str = Field(..., min_length=10, max_length=256)


class InviteRevokeInput(BaseModel):
    invite_id: str = Field(..., min_length=6, max_length=64)


class MemberRoleInput(BaseModel):
    member_user_id: str = Field(..., min_length=6, max_length=64)
    role: str = Field(..., min_length=3, max_length=10)


class MemberRemoveInput(BaseModel):
    member_user_id: str = Field(..., min_length=6, max_length=64)


class HouseholdProfileInput(BaseModel):
    name: str = Field(..., min_length=1, max_length=HOUSEHOLD_NAME_MAX_LEN)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    if not s:
        return None

    # Date-only -> start of day UTC
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        s = s + "T00:00:00Z"

    if s.endswith("Z"):
        s = s[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def split_csv(s: Optional[str]) -> Optional[List[str]]:
    if not s:
        return None
    items = [x.strip() for x in s.split(",") if x.strip()]
    return items or None


def read_version() -> str:
    candidates = [
        os.path.join(BASE_DIR, "VERSION"),
        os.path.join(BASE_DIR, "..", "VERSION"),
    ]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return APP_VERSION


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def rate_limit_key(ip: Optional[str], email: str) -> str:
    return f"{ip or 'unknown'}:{email.lower()}"


def check_rate_limit(ip: Optional[str], email: str) -> bool:
    now = time.time()
    key = rate_limit_key(ip, email)
    with _login_rate_lock:
        start, count = _login_rate.get(key, (now, 0))
        if now - start > LOGIN_RATE_WINDOW_SECONDS:
            start, count = now, 0
        count += 1
        _login_rate[key] = (start, count)
        return count <= LOGIN_RATE_MAX_ATTEMPTS


def reset_rate_limit(ip: Optional[str], email: str) -> None:
    key = rate_limit_key(ip, email)
    with _login_rate_lock:
        _login_rate.pop(key, None)


def check_lockout(ip: Optional[str], email: str) -> bool:
    key = rate_limit_key(ip, email)
    now = time.time()
    with _lockout_lock:
        until = _lockout_until.get(key)
        if until and until > now:
            return True
        if until and until <= now:
            _lockout_until.pop(key, None)
    return False


def register_login_failure(ip: Optional[str], email: str) -> bool:
    key = rate_limit_key(ip, email)
    now = time.time()
    with _lockout_lock:
        start, count = _login_failures.get(key, (now, 0))
        if now - start > LOCKOUT_WINDOW_SECONDS:
            start, count = now, 0
        count += 1
        _login_failures[key] = (start, count)
        if count >= LOCKOUT_THRESHOLD:
            _lockout_until[key] = now + LOCKOUT_DURATION_SECONDS
            _login_failures.pop(key, None)
            return True
    return False


def reset_lockout(ip: Optional[str], email: str) -> None:
    key = rate_limit_key(ip, email)
    with _lockout_lock:
        _login_failures.pop(key, None)
        _lockout_until.pop(key, None)


def check_reset_rate(ip: Optional[str], email: str) -> bool:
    now = time.time()
    key = rate_limit_key(ip, email)
    with _reset_rate_lock:
        start, count = _reset_rate.get(key, (now, 0))
        if now - start > RESET_RATE_WINDOW_SECONDS:
            start, count = now, 0
        count += 1
        _reset_rate[key] = (start, count)
        return count <= RESET_RATE_MAX_ATTEMPTS


def check_invite_rate(ip: Optional[str], email: str) -> bool:
    now = time.time()
    key = rate_limit_key(ip, email)
    with _invite_rate_lock:
        start, count = _invite_rate.get(key, (now, 0))
        if now - start > INVITE_RATE_WINDOW_SECONDS:
            start, count = now, 0
        count += 1
        _invite_rate[key] = (start, count)
        return count <= INVITE_RATE_MAX_ATTEMPTS


def check_register_rate(ip: Optional[str], email: str) -> bool:
    now = time.time()
    key = rate_limit_key(ip, email)
    with _register_rate_lock:
        start, count = _register_rate.get(key, (now, 0))
        if now - start > REGISTER_RATE_WINDOW_SECONDS:
            start, count = now, 0
        count += 1
        _register_rate[key] = (start, count)
        return count <= REGISTER_RATE_MAX_ATTEMPTS


def check_verify_rate(ip: Optional[str], email: str) -> bool:
    now = time.time()
    key = rate_limit_key(ip, email)
    with _verify_rate_lock:
        start, count = _verify_rate.get(key, (now, 0))
        if now - start > VERIFY_RATE_WINDOW_SECONDS:
            start, count = now, 0
        count += 1
        _verify_rate[key] = (start, count)
        return count <= VERIFY_RATE_MAX_ATTEMPTS


def ensure_csrf_cookie(request: Request, response: Response, rotate: bool = False) -> str:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if rotate or not token:
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            httponly=False,
            samesite="strict",
            secure=ANNAFINDER_ENV == "prod",
            max_age=SESSION_TTL_SECONDS,
            path="/",
        )
    return token


def get_allowed_origins() -> List[str]:
    return list(CORS_ALLOWED_ORIGINS)


def origin_from_headers(request: Request) -> Optional[str]:
    origin = request.headers.get("origin")
    if origin:
        return origin
    ref = request.headers.get("referer")
    if not ref:
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(ref)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    method = request.method.upper()
    path = request.url.path
    if method in MUTATING_METHODS and path != "/healthz":
        raise HTTPException(status_code=403, detail="Origin required")
    return None


def is_origin_allowed(origin: Optional[str]) -> bool:
    if not origin:
        return False
    return origin in get_allowed_origins()


def require_allowed_origin(request: Request) -> str:
    try:
        origin = origin_from_headers(request)
    except HTTPException as exc:
        raise HTTPException(status_code=403, detail=exc.detail) from exc
    if not origin or not is_origin_allowed(origin):
        raise HTTPException(status_code=403, detail="Origin not allowed")
    return origin


def require_csrf_double_submit(request: Request) -> tuple[str, str]:
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
    csrf_header = request.headers.get("X-CSRF-Token", "")
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF failed")
    return csrf_cookie, csrf_header


def db() -> sqlite3.Connection:
    # Avoid startup failures if another process briefly holds a lock.
    con = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA busy_timeout = 10000")
    except sqlite3.DatabaseError:
        pass
    return con


def normalize_role(role: Optional[str]) -> str:
    if not role:
        return ""
    return role.strip().upper()


def get_member_role(user_id: str, household_id: str) -> str:
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT role FROM family_members WHERE user_id = ? AND family_id = ?",
        (user_id, household_id),
    )
    row = cur.fetchone()
    con.close()
    return normalize_role(row["role"]) if row and row["role"] is not None else ""


def is_email_verified(session: Dict[str, Any]) -> bool:
    return bool(session.get("email_verified_at"))


SENSITIVE_EMAIL_PERMISSIONS = {
    PERM_INVITE_CREATE,
    PERM_INVITE_REVOKE,
    PERM_INVITE_ACCEPT,
    PERM_MEMBER_ROLE_CHANGE,
    PERM_MEMBER_REMOVE,
    PERM_DATA_EXPORT,
    PERM_DATA_DELETE,
    PERM_HOUSEHOLD_PROFILE_UPDATE,
}


def count_household_owners(household_id: str) -> int:
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT COUNT(*) AS c FROM family_members WHERE family_id = ? AND UPPER(role) = ?",
        (household_id, ROLE_OWNER),
    )
    count = cur.fetchone()["c"]
    con.close()
    return count


def mask_email(email: str) -> str:
    if "@" not in email:
        return sanitize_str(email, 120)
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked_local = local[0:1] + "*"
    else:
        masked_local = local[:2] + "***"
    return sanitize_str(f"{masked_local}@{domain}", 120)


def choose_lang(request: Request) -> str:
    accept_lang = (request.headers.get("accept-language") or "").lower()
    if "pt" in accept_lang:
        return "pt"
    return "en"


def smtp_configured() -> bool:
    return bool(os.getenv("SMTP_HOST", "").strip())


def validate_email_settings() -> None:
    if not smtp_configured():
        return
    if ANNAFINDER_ENV != "dev" and not BASE_URL.startswith("https://"):
        raise RuntimeError(
            "ANNAFINDER_BASE_URL must be https:// when SMTP is configured outside dev."
        )


EMAIL_SUBJECTS = {
    "reset_request": {
        "en": "Reset your AnnaFinder password",
        "pt": "Reposicao de palavra-passe AnnaFinder",
    },
    "reset_done": {
        "en": "Your AnnaFinder password was reset",
        "pt": "Palavra-passe AnnaFinder reposta",
    },
    "invite": {"en": "You are invited to AnnaFinder", "pt": "Convite para AnnaFinder"},
    "verify_email": {
        "en": "Verify your AnnaFinder email",
        "pt": "Verifique o seu email AnnaFinder",
    },
}


def enqueue_email_template(
    template: str,
    lang: str,
    to_email: str,
    context: Dict[str, str],
    correlation_id: str,
    household_id: Optional[str],
    user_id: Optional[str],
) -> None:
    subject = EMAIL_SUBJECTS.get(template, {}).get(
        lang, EMAIL_SUBJECTS.get(template, {}).get("en", "")
    )
    body_text = render_email_body(template, lang, context)
    enqueue_email(
        DB_PATH,
        to_email,
        template,
        subject,
        body_text,
        None,
        "pending",
        correlation_id,
        household_id,
        user_id,
    )


def ensure_column(con: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    table_name = validate_identifier(table)
    column_name = validate_identifier(column)
    if table_name not in KNOWN_TABLES:
        raise ValueError(f"Unknown table: {table_name}")
    col_type_name = validate_sqlite_col_type(col_type)
    cur = con.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    cols = [r["name"] for r in cur.fetchall()]
    if column_name in cols:
        return
    cur.execute(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type_name} NOT NULL DEFAULT ''"
    )


def ensure_nullable_column(con: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    table_name = validate_identifier(table)
    column_name = validate_identifier(column)
    if table_name not in KNOWN_TABLES:
        raise ValueError(f"Unknown table: {table_name}")
    col_type_name = validate_sqlite_col_type(col_type)
    cur = con.cursor()
    cur.execute(f"PRAGMA table_info({table_name})")
    cols = [r["name"] for r in cur.fetchall()]
    if column_name in cols:
        return
    cur.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type_name}")


def init_db() -> None:
    con = db()
    cur = con.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            icon TEXT NOT NULL,
            location TEXT NOT NULL,
            battery INTEGER NOT NULL DEFAULT 100,
            notes TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL DEFAULT '',
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            actor TEXT NOT NULL DEFAULT 'family',
            archived INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            family_id TEXT,
            actor_user_id TEXT,
            entity TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            success INTEGER NOT NULL DEFAULT 1,
            target_type TEXT,
            target_id TEXT,
            ip TEXT,
            user_agent TEXT,
            payload_json TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS routines (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            items_csv TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS family_members (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL DEFAULT '',
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            email_verified_at TEXT,
            pending_email TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS households (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            profile_complete INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS household_members (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            household_id TEXT NOT NULL,
            session_token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            request_ip_hash TEXT NOT NULL DEFAULT ''
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL,
            request_ip_hash TEXT NOT NULL DEFAULT ''
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_outbox (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            to_email TEXT NOT NULL,
            template TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_text TEXT NOT NULL,
            body_html TEXT,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            correlation_id TEXT NOT NULL DEFAULT '',
            household_id TEXT NOT NULL DEFAULT '',
            user_id TEXT NOT NULL DEFAULT ''
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            page TEXT NOT NULL,
            rating INTEGER,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            request_id TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS household_invites (
            id TEXT PRIMARY KEY,
            household_id TEXT NOT NULL,
            inviter_user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            revoked_at TEXT,
            email_hint TEXT NOT NULL DEFAULT '',
            role_to_assign TEXT NOT NULL
        )
        """
    )

    ensure_column(con, "items", "household_id", "TEXT")
    ensure_column(con, "events", "household_id", "TEXT")
    ensure_column(con, "routines", "household_id", "TEXT")
    ensure_column(con, "family_members", "household_id", "TEXT")
    ensure_column(con, "sessions", "created_at", "TEXT")
    ensure_column(con, "sessions", "last_seen_at", "TEXT")
    ensure_column(con, "sessions", "expires_at", "TEXT")
    ensure_column(con, "households", "profile_complete", "INTEGER")
    ensure_nullable_column(con, "users", "email_verified_at", "TEXT")
    ensure_nullable_column(con, "users", "pending_email", "TEXT")

    con.commit()
    con.close()


def add_event(
    kind: str, message: str, details: str = "", actor: str = "family", household_id: str = ""
) -> None:
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO events (id, household_id, ts, kind, message, details, actor, archived)
        VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """,
        (str(uuid.uuid4()), household_id, iso_utc(now_utc()), kind, message, details, actor),
    )
    con.commit()
    con.close()


def seed_if_empty() -> None:
    con = db()
    cur = con.cursor()

    def add_event_in_tx(
        kind: str, message: str, details: str = "", actor: str = "family", household_id: str = ""
    ) -> None:
        cur.execute(
            """
            INSERT INTO events (id, household_id, ts, kind, message, details, actor, archived)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (str(uuid.uuid4()), household_id, iso_utc(now_utc()), kind, message, details, actor),
        )

    cur.execute("SELECT id FROM households ORDER BY created_at ASC LIMIT 1")
    row = cur.fetchone()
    if row:
        household_id = row["id"]
    else:
        household_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO households (id, name, created_at)
            VALUES (?, ?, ?)
            """,
            (household_id, "Demo Family", iso_utc(now_utc())),
        )
    cur.execute(
        "UPDATE households SET profile_complete = 1 WHERE id = ?",
        (household_id,),
    )

    cur.execute("SELECT id FROM users WHERE email = ?", ("demo@annafinder.local",))
    user = cur.fetchone()
    if user:
        user_id = user["id"]
    else:
        user_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO users (id, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, "demo@annafinder.local", hash_password("Demo1234!"), iso_utc(now_utc())),
        )
    cur.execute(
        """
        UPDATE users
        SET email_verified_at = COALESCE(email_verified_at, ?)
        WHERE id = ?
        """,
        (iso_utc(now_utc()), user_id),
    )

    cur.execute(
        """
        SELECT id FROM household_members
        WHERE household_id = ? AND user_id = ?
        """,
        (household_id, user_id),
    )
    if not cur.fetchone():
        cur.execute(
            """
            INSERT INTO household_members (id, household_id, user_id, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), household_id, user_id, ROLE_OWNER, iso_utc(now_utc())),
        )

    cur.execute("SELECT id FROM users WHERE email = ?", ("viewer@annafinder.local",))
    viewer = cur.fetchone()
    if viewer:
        viewer_id = viewer["id"]
    else:
        viewer_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO users (id, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                viewer_id,
                "viewer@annafinder.local",
                hash_password("Viewer1234!"),
                iso_utc(now_utc()),
            ),
        )
    cur.execute(
        """
        UPDATE users
        SET email_verified_at = COALESCE(email_verified_at, ?)
        WHERE id = ?
        """,
        (iso_utc(now_utc()), viewer_id),
    )

    cur.execute(
        """
        SELECT id FROM household_members
        WHERE household_id = ? AND user_id = ?
        """,
        (household_id, viewer_id),
    )
    if not cur.fetchone():
        cur.execute(
            """
            INSERT INTO household_members (id, household_id, user_id, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), household_id, viewer_id, ROLE_VIEWER, iso_utc(now_utc())),
        )

    cur.execute("SELECT id FROM users WHERE email = ?", ("reset@annafinder.local",))
    reset_user = cur.fetchone()
    if reset_user:
        reset_user_id = reset_user["id"]
    else:
        reset_user_id = str(uuid.uuid4())
        cur.execute(
            """
            INSERT INTO users (id, email, password_hash, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                reset_user_id,
                "reset@annafinder.local",
                hash_password("Reset1234!"),
                iso_utc(now_utc()),
            ),
        )
    cur.execute(
        """
        UPDATE users
        SET email_verified_at = COALESCE(email_verified_at, ?)
        WHERE id = ?
        """,
        (iso_utc(now_utc()), reset_user_id),
    )

    cur.execute(
        """
        SELECT id FROM household_members
        WHERE household_id = ? AND user_id = ?
        """,
        (household_id, reset_user_id),
    )
    if not cur.fetchone():
        cur.execute(
            """
            INSERT INTO household_members (id, household_id, user_id, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), household_id, reset_user_id, ROLE_MEMBER, iso_utc(now_utc())),
        )

    cur.execute("UPDATE items SET household_id = ? WHERE household_id = ''", (household_id,))
    cur.execute("UPDATE events SET household_id = ? WHERE household_id = ''", (household_id,))
    cur.execute("UPDATE routines SET household_id = ? WHERE household_id = ''", (household_id,))
    cur.execute(
        "UPDATE family_members SET household_id = ? WHERE household_id = ''", (household_id,)
    )

    cur.execute("SELECT COUNT(*) AS c FROM family_members")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            """
            INSERT INTO family_members (id, household_id, name, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (str(uuid.uuid4()), household_id, "Family Admin", "admin", iso_utc(now_utc())),
        )

    cur.execute("SELECT COUNT(*) AS c FROM items")
    if cur.fetchone()["c"] == 0:
        now = iso_utc(now_utc())
        demo_items = [
            ("wallet", "Wallet", "ÐY'>", "Kitchen", 100),
            ("keys", "Keys", "ÐY'", "Living room", 85),
            ("glasses", "Glasses", "ÐY'", "Bedroom", 92),
            ("phone", "Phone", "ÐYñ", "Office", 80),
        ]
        for iid, name, icon, loc, bat in demo_items:
            cur.execute(
                """
                INSERT INTO items (id, household_id, name, icon, location, battery, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, '', ?, ?)
                """,
                (iid, household_id, name, icon, loc, bat, now, now),
            )
        add_event_in_tx(
            "seed", "Demo data seeded", "Initial items created", household_id=household_id
        )

    cur.execute("SELECT COUNT(*) AS c FROM routines")
    if cur.fetchone()["c"] == 0:
        now = iso_utc(now_utc())
        routines = [
            ("leave_home", "Leaving home", "Keys,Wallet,Phone,Glasses"),
            ("bedtime", "Bedtime", "Phone charger,Front door locked,Water on bedside"),
        ]
        for rid, name, items_csv in routines:
            cur.execute(
                """
                INSERT INTO routines (id, household_id, name, items_csv, enabled, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (rid, household_id, name, items_csv, now, now),
            )
        add_event_in_tx(
            "seed", "Demo routines seeded", "Leaving home + Bedtime", household_id=household_id
        )

    con.commit()
    con.close()


def fetch_export_payload(family_id: str) -> Dict[str, Any]:
    household_id = family_id
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT id, name, icon, location, battery, notes, created_at, updated_at FROM items WHERE household_id = ?",
        (household_id,),
    )
    items = [dict(r) for r in cur.fetchall()]
    cur.execute(
        "SELECT id, ts, kind, message, details, actor, archived FROM events WHERE household_id = ?",
        (household_id,),
    )
    events = [dict(r) for r in cur.fetchall()]
    cur.execute(
        "SELECT id, name, items_csv, enabled, created_at, updated_at FROM routines WHERE household_id = ?",
        (household_id,),
    )
    routines = [dict(r) for r in cur.fetchall()]
    cur.execute(
        "SELECT id, name, role, created_at FROM family_members WHERE household_id = ?",
        (household_id,),
    )
    family_members = [dict(r) for r in cur.fetchall()]
    con.close()
    return {
        "items": items,
        "events": events,
        "routines": routines,
        "family_members": family_members,
    }


def clear_all_data(household_id: str) -> Dict[str, int]:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM items WHERE household_id = ?", (household_id,))
    items_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM events WHERE household_id = ?", (household_id,))
    events_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM routines WHERE household_id = ?", (household_id,))
    routines_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM family_members WHERE household_id = ?", (household_id,))
    family_count = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) AS c FROM feedback WHERE household_id = ?", (household_id,))
    feedback_count = cur.fetchone()["c"]

    cur.execute("DELETE FROM items WHERE household_id = ?", (household_id,))
    cur.execute("DELETE FROM events WHERE household_id = ?", (household_id,))
    cur.execute("DELETE FROM routines WHERE household_id = ?", (household_id,))
    cur.execute("DELETE FROM family_members WHERE household_id = ?", (household_id,))
    cur.execute("DELETE FROM feedback WHERE household_id = ?", (household_id,))
    con.commit()
    con.close()
    return {
        "items": items_count,
        "events": events_count,
        "routines": routines_count,
        "family_members": family_count,
        "feedback": feedback_count,
    }


def reset_db() -> None:
    if ANNAFINDER_ENV != "test":
        return
    try:
        if os.path.exists(DB_PATH):
            try:
                from backend.db import session as db_session

                db_session.engine.dispose()
            except ImportError:
                pass
            os.remove(DB_PATH)
    except OSError:
        pass
    alembic_upgrade_head(DATABASE_URL)
    session = SessionLocal()
    try:
        seed_demo_data(session)
    finally:
        session.close()


def _clear_db_schema() -> None:
    con = db()
    try:
        cur = con.cursor()
        cur.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
              AND name NOT LIKE 'sqlite_%'
            """
        )
        tables = [row["name"] for row in cur.fetchall()]
        for table in tables:
            cur.execute(f"DROP TABLE IF EXISTS {table}")
        con.commit()
    finally:
        con.close()
    with _metrics_lock:
        _metrics["requests_total"] = 0
        _metrics["status_2xx"] = 0
        _metrics["status_4xx"] = 0
        _metrics["status_5xx"] = 0
        _metrics["latency_ms_sum"] = 0.0


def purge_expired_delete_tokens() -> None:
    now = time.time()
    with _delete_tokens_lock:
        expired = [k for k, (exp, _) in _delete_tokens.items() if exp <= now]
        for k in expired:
            _delete_tokens.pop(k, None)


def issue_delete_token(household_id: str, ttl_seconds: int = 300) -> Dict[str, Any]:
    purge_expired_delete_tokens()
    token = str(uuid.uuid4())
    expires_at = time.time() + ttl_seconds
    with _delete_tokens_lock:
        _delete_tokens[token] = (expires_at, household_id)
    return {"delete_token": token, "expires_in_sec": ttl_seconds}


def consume_delete_token(token: str, household_id: str) -> bool:
    purge_expired_delete_tokens()
    with _delete_tokens_lock:
        entry = _delete_tokens.pop(token, None)
    if entry is None:
        return False
    exp, token_household = entry
    if token_household != household_id:
        return False
    return exp > time.time()


def hash_verify_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_email_verification(user_id: str, request_ip: Optional[str]) -> str:
    token = secrets.token_urlsafe(48)
    token_hash = hash_verify_token(token)
    created_at = iso_utc(now_utc())
    expires_at = iso_utc(now_utc() + timedelta(seconds=EMAIL_VERIFY_TTL_SECONDS))
    ip_hash = safe_hash(request_ip or "")
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO email_verifications (id, user_id, token_hash, expires_at, used_at, created_at, request_ip_hash)
        VALUES (?, ?, ?, ?, NULL, ?, ?)
        """,
        (str(uuid.uuid4()), user_id, token_hash, expires_at, created_at, ip_hash),
    )
    con.commit()
    con.close()
    return token


def consume_email_verification(token: str) -> Optional[str]:
    token_hash = hash_verify_token(token)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, user_id, expires_at, used_at
        FROM email_verifications
        WHERE token_hash = ?
        """,
        (token_hash,),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        return None
    if row["used_at"]:
        con.close()
        return None
    expires = parse_dt(row["expires_at"])
    if not expires or expires < now_utc():
        con.close()
        return None
    cur.execute(
        "UPDATE email_verifications SET used_at = ? WHERE id = ?",
        (iso_utc(now_utc()), row["id"]),
    )
    con.commit()
    con.close()
    return row["user_id"]


def hash_invite_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_invite(
    household_id: str,
    inviter_user_id: str,
    role: str,
    email_hint: str,
    ttl_days: int = 7,
) -> Tuple[str, str]:
    token = secrets.token_urlsafe(48)
    token_hash = hash_invite_token(token)
    invite_id = str(uuid.uuid4())
    created_at = iso_utc(now_utc())
    expires_at = iso_utc(now_utc() + timedelta(days=ttl_days))
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO household_invites (
            id, household_id, inviter_user_id, token_hash, created_at, expires_at, used_at, revoked_at, email_hint, role_to_assign
        )
        VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
        """,
        (
            invite_id,
            household_id,
            inviter_user_id,
            token_hash,
            created_at,
            expires_at,
            sanitize_str(email_hint, 120),
            role,
        ),
    )
    con.commit()
    con.close()
    return invite_id, token


def get_invite_by_token(token: str) -> Optional[sqlite3.Row]:
    token_hash = hash_invite_token(token)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, household_id, inviter_user_id, expires_at, used_at, revoked_at, role_to_assign
        FROM household_invites
        WHERE token_hash = ?
        """,
        (token_hash,),
    )
    row = cur.fetchone()
    con.close()
    return row


def get_session_from_cookie(request: Request) -> Optional[Dict[str, Any]]:
    token = request.cookies.get(get_session_cookie_name())
    if not token:
        return None
    token_hash = hash_session_token(token)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT s.id, s.user_id, s.household_id, s.expires_at, s.created_at, s.last_seen_at,
               u.email, u.email_verified_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_token_hash = ?
        """,
        (token_hash,),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        return None
    expires = parse_dt(row["expires_at"])
    created = parse_dt(row["created_at"])
    last_seen = parse_dt(row["last_seen_at"])
    now = now_utc()
    expired_reason = ""
    if not expires or expires < now:
        expired_reason = "absolute_expired"
    elif created and created + timedelta(seconds=SESSION_ABSOLUTE_TIMEOUT_SECONDS) < now:
        expired_reason = "absolute_timeout"
    elif last_seen and last_seen + timedelta(seconds=SESSION_IDLE_TIMEOUT_SECONDS) < now:
        expired_reason = "idle_timeout"

    if expired_reason:
        cur.execute("DELETE FROM sessions WHERE id = ?", (row["id"],))
        con.commit()
        con.close()
        session_data = dict(row)
        session_data["family_id"] = session_data.get("household_id", "")
        ctx = build_security_context(
            request,
            {"user_id": session_data["user_id"], "household_id": session_data["household_id"]},
        )
        emit_event(
            {
                **ctx,
                "event": "AUTH_SESSION_EXPIRED",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "session"},
                "meta": {"reason": expired_reason},
            }
        )
        return None
    cur.execute(
        "UPDATE sessions SET last_seen_at = ? WHERE id = ?",
        (iso_utc(now), row["id"]),
    )
    con.commit()
    con.close()
    session_data = dict(row)
    session_data["family_id"] = session_data.get("household_id", "")
    con.close()
    return {
        "user_id": session_data["user_id"],
        "household_id": session_data["household_id"],
        "family_id": session_data["family_id"],
        "email": session_data["email"],
        "email_verified_at": session_data["email_verified_at"],
        "auth_type": "cookie",
    }


def _get_session_from_bearer_token(request: Request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    _, _, token = auth_header.partition(" ")
    token = token.strip()
    if not token:
        return None
    try:
        payload = decode_token(token)
    except PyJWTError:
        return None
    if payload.get("token_type") != "access":
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    return {
        "user_id": user_id,
        "household_id": "",
        "family_id": "",
        "email": payload.get("email", ""),
        "email_verified_at": payload.get("email_verified_at"),
        "auth_type": "bearer",
    }


def require_session(request: Request) -> Dict[str, Any]:
    session = get_session_from_cookie(request)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return session


def build_security_context(
    request: Request, session: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    session_cookie = request.cookies.get(get_session_cookie_name(), "")
    actor_ctx = {
        "user_id": session.get("user_id") if session else "",
        "household_id": session.get("household_id") if session else "",
        "session_hash": safe_hash(session_cookie),
    }
    return {
        "request_id": get_request_id(request),
        "actor": build_actor(actor_ctx),
        "source": {
            "ip": sanitize_str(request.client.host if request.client else ""),
            "user_agent": sanitize_str(request.headers.get("user-agent", ""), 128),
        },
    }


def emit_email_event(
    event: Dict[str, Any], correlation_id: str, household_id: Optional[str], user_id: Optional[str]
) -> None:
    event["request_id"] = sanitize_str(correlation_id, 64)
    event["actor"] = build_actor(
        {"user_id": user_id or "", "household_id": household_id or "", "session_hash": ""}
    )
    if "source" not in event:
        event["source"] = {}
    emit_event(event)


def _is_csrf_exempt_path(path: str) -> bool:
    return (
        path in CSRF_SAFE_PATHS
        or any(path.startswith(prefix) for prefix in CSRF_SAFE_PREFIXES)
        or (ANNAFINDER_ENV in ("test", "dev") and path in CSRF_DEV_PATHS)
    )


def _check_origin(request: Request) -> Tuple[bool, Optional[str], Optional[str]]:
    try:
        origin = origin_from_headers(request)
    except HTTPException:
        return False, None, "missing_origin"
    if not origin:
        return False, None, "missing_origin"
    if not is_origin_allowed(origin):
        return False, origin, "origin_check"
    return True, origin, None


def _csrf_error(message: str, status_code: int) -> JSONResponse:
    payload = make_error_payload(ERROR_CODES["http"], message, {"status_code": status_code})
    payload_with_detail = {**payload, "detail": payload["error"]["message"]}
    return JSONResponse(status_code=status_code, content=payload_with_detail)

@app.middleware("http")
async def csrf_protect(request: Request, call_next):
    method = request.method.upper()
    path = request.url.path
    if method not in MUTATING_METHODS or _is_csrf_exempt_path(path):
        return await call_next(request)

    session: Optional[Dict[str, Any]] = None
    if path not in AUTH_STATE_PATHS:
        session = get_session_from_cookie(request) or _get_session_from_bearer_token(request)
        if not session:
            return _csrf_error("Not authenticated", 401)

    is_bearer = session is not None and session.get("auth_type") == "bearer"
    if not is_bearer:
        origin_ok, origin, reason = _check_origin(request)
        if not origin_ok:
            ctx = build_security_context(request)
            emit_event(
                {
                    **ctx,
                    "event": "CSRF_FAIL",
                    "severity": "HIGH",
                    "outcome": "FAIL",
                    "target": {"resource": sanitize_str(path)},
                    "meta": {"reason": reason or "origin_check"},
                }
            )
            return _csrf_error("CSRF origin failed", 403)

        csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            ctx = build_security_context(request, session)
            emit_event(
                {
                    **ctx,
                    "event": "CSRF_FAIL",
                    "severity": "HIGH",
                    "outcome": "FAIL",
                    "target": {"resource": sanitize_str(path)},
                    "meta": {"reason": "token_mismatch"},
                }
            )
            return _csrf_error("CSRF failed", 403)

    return await call_next(request)


@app.middleware("http")
async def request_logger(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    token = set_active_request_id(request_id)
    request.state.request_id = request_id
    start = time.perf_counter()
    status_code = 500
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    response = None

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    except Exception as exc:
        error_type = type(exc).__name__
        error_message = str(exc)[:200] if ANNAFINDER_ENV != "prod" else None
        raise
    finally:
        duration_ms = (time.perf_counter() - start) * 1000.0
        client_ip = request.client.host if request.client else None
        level = logging.INFO
        if status_code >= 500:
            level = logging.ERROR
        elif status_code >= 400:
            level = logging.WARNING
        fields = {
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "duration_ms": round(duration_ms, 2),
            "client_ip": client_ip,
            "env": ANNAFINDER_ENV,
            "message": "request complete",
        }
        if error_type:
            fields["error_type"] = error_type
            if error_message:
                fields["error_message"] = error_message
        log_structured(level, "request", **fields)
        if response is not None:
            response.headers["X-Request-Id"] = request_id
        reset_active_request_id(token)

        with _metrics_lock:
            _metrics["requests_total"] += 1
            if 200 <= status_code < 300:
                _metrics["status_2xx"] += 1
            elif 400 <= status_code < 500:
                _metrics["status_4xx"] += 1
            else:
                _metrics["status_5xx"] += 1
            _metrics["latency_ms_sum"] += duration_ms

    response.headers["X-Request-Id"] = request_id
    return response


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

    path = request.url.path or ""
    if path.startswith("/auth") or path.startswith("/api/v1/auth"):
        response.headers["Cache-Control"] = "no-store"

    if ANNAFINDER_ENV == "prod" and BASE_URL.startswith("https://"):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
        )

    return response


if ANNAFINDER_ENV == "test":

    @app.post("/__test__/reset")
    def reset_db_endpoint() -> Dict[str, bool]:
        reset_db()
        return {"ok": True}

    @app.post("/__test__/emails/flush")
    def flush_outbox() -> Dict[str, int]:
        return send_pending_emails(DB_PATH, emit_event_fn=emit_email_event)

    @app.get("/__test__/emails/outbox")
    def get_outbox(limit: int = 20) -> Dict[str, Any]:
        con = db()
        cur = con.cursor()
        cur.execute(
            """
            SELECT id, created_at, to_email, template, subject, body_text, status, attempts, last_error
            FROM email_outbox
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        con.close()
        return {"items": rows}


@app.post("/__csp_report")
async def csp_report(request: Request) -> Response:
    client_ip = request.client.host if request.client else "unknown"
    if not _allow_csp_report(client_ip):
        return _csp_error(429, "Too many CSP reports from this client")

    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()
    allowed_media_types = {"application/reports+json", "application/csp-report"}
    if media_type not in allowed_media_types:
        return _csp_error(415, "CSP reports must use an allowed content-type")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            length = int(content_length)
        except ValueError:
            return _csp_error(400, "Invalid Content-Length")
        if length > MAX_CSP_REPORT_BYTES:
            return _csp_error(413, "CSP report payload too large")

    ok, size = await _consume_csp_body(request)
    if not ok:
        return _csp_error(413, "CSP report payload too large")

    logger.info(
        json.dumps(
            {
                "event": "CSP_REPORT",
                "size": size,
                "content_type": media_type,
                "ip": client_ip,
                "outcome": "accepted",
            }
        )
    )
    return Response(status_code=204)


def _csp_error(status: int, message: str) -> JSONResponse:
    payload = make_error_payload(ERROR_CODES["http"], message, {"status_code": status})
    payload_with_detail = {**payload, "detail": payload["error"]["message"]}
    return JSONResponse(status_code=status, content=payload_with_detail)


def _allow_csp_report(client_ip: str) -> bool:
    now = monotonic()
    queue = _csp_rate_limits[client_ip]
    while queue and queue[0] <= now - CSP_REPORT_WINDOW:
        queue.popleft()
    if len(queue) >= CSP_REPORT_RATE_LIMIT:
        return False
    queue.append(now)
    return True


async def _consume_csp_body(request: Request) -> Tuple[bool, int]:
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_CSP_REPORT_BYTES:
            return False, total
    return True, total


def _reset_csp_rate_limits() -> None:
    _csp_rate_limits.clear()


@app.post("/auth/register")
def register(data: RegisterInput, request: Request) -> Dict[str, Any]:
    require_allowed_origin(request)
    require_csrf_double_submit(request)
    ip = request.client.host if request.client else None
    email = sanitize_str((data.email or "").strip().lower(), 200)
    if not email:
        return {"ok": True, "message": "Check your email for a verification link."}

    if not check_register_rate(ip, email):
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_REGISTER",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/register"},
                "meta": {"reason": "rate_limit", "email_hash": safe_hash(email)},
            }
        )
        return {"ok": True, "message": "Check your email for a verification link."}

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id, email_verified_at FROM users WHERE email = ?", (email,))
    existing = cur.fetchone()
    lang = choose_lang(request)
    if existing:
        if not existing["email_verified_at"]:
            token = create_email_verification(existing["id"], ip)
            verify_link = f"{BASE_URL}/verify-email?token={token}"
            enqueue_email_template(
                "verify_email",
                lang,
                email,
                {
                    "app_name": "AnnaFinder",
                    "verify_link": verify_link,
                    "expires_minutes": str(int(EMAIL_VERIFY_TTL_SECONDS / 60)),
                },
                get_request_id(request),
                None,
                existing["id"],
            )
            emit_event(
                {
                    **build_security_context(request),
                    "event": "EMAIL_ENQUEUED",
                    "severity": "LOW",
                    "outcome": "SUCCESS",
                    "target": {"resource": "/auth/register"},
                    "meta": {"template": "verify_email"},
                }
            )
        con.close()
        return {"ok": True, "message": "Check your email for a verification link."}

    user_id = str(uuid.uuid4())
    household_id = str(uuid.uuid4())
    name = sanitize_str((data.household_name or "").strip(), HOUSEHOLD_NAME_MAX_LEN)
    household_name = name or "My Household"
    profile_complete = 1 if name else 0
    created_at = iso_utc(now_utc())

    cur.execute(
        """
        INSERT INTO users (id, email, password_hash, created_at, email_verified_at, pending_email)
        VALUES (?, ?, ?, ?, NULL, NULL)
        """,
        (user_id, email, hash_password(data.password), created_at),
    )
    cur.execute(
        """
        INSERT INTO households (id, name, created_at, profile_complete)
        VALUES (?, ?, ?, ?)
        """,
        (household_id, household_name, created_at, profile_complete),
    )
    cur.execute(
        """
        INSERT INTO household_members (id, household_id, user_id, role, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), household_id, user_id, ROLE_OWNER, created_at),
    )
    cur.execute(
        """
        INSERT INTO family_members (id, household_id, name, role, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), household_id, "Household owner", "owner", created_at),
    )
    con.commit()
    con.close()

    emit_event(
        {
            **build_security_context(request),
            "event": "AUTH_REGISTER",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/register"},
            "meta": {"email_hash": safe_hash(email)},
        }
    )

    token = create_email_verification(user_id, ip)
    verify_link = f"{BASE_URL}/verify-email?token={token}"
    enqueue_email_template(
        "verify_email",
        lang,
        email,
        {
            "app_name": "AnnaFinder",
            "verify_link": verify_link,
            "expires_minutes": str(int(EMAIL_VERIFY_TTL_SECONDS / 60)),
        },
        get_request_id(request),
        household_id,
        user_id,
    )
    emit_event(
        {
            **build_security_context(request),
            "event": "EMAIL_ENQUEUED",
            "severity": "LOW",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/register"},
            "meta": {"template": "verify_email"},
        }
    )

    return {"ok": True, "message": "Check your email for a verification link."}


@app.get("/auth/verify-email/confirm")
def verify_email_confirm(token: str, request: Request) -> Dict[str, Any]:
    user_id = consume_email_verification(token)
    if not user_id:
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_EMAIL_VERIFY",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/verify-email/confirm"},
            }
        )
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired token"})

    con = db()
    cur = con.cursor()
    cur.execute(
        "UPDATE users SET email_verified_at = ? WHERE id = ?",
        (iso_utc(now_utc()), user_id),
    )
    con.commit()
    con.close()

    ctx = build_security_context(request, {"user_id": user_id, "household_id": ""})
    emit_event(
        {
            **ctx,
            "event": "AUTH_EMAIL_VERIFY",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/verify-email/confirm"},
        }
    )
    return {"ok": True, "message": "Email verified"}


@app.post("/auth/verify-email/resend")
def verify_email_resend(data: VerifyResendInput, request: Request) -> Dict[str, Any]:
    session = get_session_from_cookie(request)
    email = (data.email or (session.get("email") if session else "") or "").strip().lower()
    ip = request.client.host if request.client else None
    if not email:
        return {"ok": True, "message": "Check your email for a verification link."}
    if not check_verify_rate(ip, email):
        ctx = build_security_context(request, session)
        emit_event(
            {
                **ctx,
                "event": "AUTH_EMAIL_VERIFY_RESEND",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/verify-email/resend"},
                "meta": {"reason": "rate_limit", "email_hash": safe_hash(email)},
            }
        )
        return {"ok": True, "message": "Check your email for a verification link."}

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id, email_verified_at FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    if not user or user["email_verified_at"]:
        con.close()
        return {"ok": True, "message": "Check your email for a verification link."}

    token = create_email_verification(user["id"], ip)
    verify_link = f"{BASE_URL}/verify-email?token={token}"
    lang = choose_lang(request)
    enqueue_email_template(
        "verify_email",
        lang,
        email,
        {
            "app_name": "AnnaFinder",
            "verify_link": verify_link,
            "expires_minutes": str(int(EMAIL_VERIFY_TTL_SECONDS / 60)),
        },
        get_request_id(request),
        None,
        user["id"],
    )
    con.close()
    emit_event(
        {
            **build_security_context(request, session),
            "event": "AUTH_EMAIL_VERIFY_RESEND",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/verify-email/resend"},
        }
    )
    emit_event(
        {
            **build_security_context(request, session),
            "event": "EMAIL_ENQUEUED",
            "severity": "LOW",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/verify-email/resend"},
            "meta": {"template": "verify_email"},
        }
    )
    return {"ok": True, "message": "Check your email for a verification link."}


@app.post("/auth/login")
def login(data: LoginInput, request: Request, response: Response) -> Dict[str, Any]:
    require_allowed_origin(request)
    require_csrf_double_submit(request)
    ip = request.client.host if request.client else None
    email = (data.email or "").strip().lower()
    if check_lockout(ip, email):
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_LOCKOUT_SOFT",
                "severity": "HIGH",
                "outcome": "FAIL",
                "target": {"resource": "/auth/login"},
                "meta": {"email_hash": safe_hash(email)},
            }
        )
        raise HTTPException(status_code=429, detail="Too many attempts, try again later")

    if not check_rate_limit(ip, email):
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_LOGIN_FAIL",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/login"},
                "meta": {"reason": "rate_limit", "email_hash": safe_hash(email)},
            }
        )
        raise HTTPException(status_code=429, detail="Too many attempts, try again later")

    existing = request.cookies.get(get_session_cookie_name())
    if existing:
        token_hash = hash_session_token(existing)
        con = db()
        cur = con.cursor()
        cur.execute("DELETE FROM sessions WHERE session_token_hash = ?", (token_hash,))
        con.commit()
        con.close()
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_SESSION_ROTATE",
                "severity": "INFO",
                "outcome": "SUCCESS",
                "target": {"resource": "/auth/login"},
            }
        )

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    if not user or not verify_password(data.password, user["password_hash"]):
        con.close()
        if register_login_failure(ip, email):
            ctx = build_security_context(request)
            emit_event(
                {
                    **ctx,
                    "event": "AUTH_LOCKOUT_SOFT",
                    "severity": "HIGH",
                    "outcome": "FAIL",
                    "target": {"resource": "/auth/login"},
                    "meta": {"email_hash": safe_hash(email)},
                }
            )
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_LOGIN_FAIL",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/login"},
                "meta": {"reason": "invalid_credentials", "email_hash": safe_hash(email)},
            }
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    reset_rate_limit(ip, email)

    cur.execute(
        """
        SELECT f.id, f.name
        FROM family_members fm
        JOIN families f ON f.id = fm.family_id
        WHERE fm.user_id = ?
        ORDER BY fm.created_at ASC
        LIMIT 1
        """,
        (user["id"],),
    )
    family = cur.fetchone()
    if not family:
        con.close()
        raise HTTPException(status_code=403, detail="No family assigned")

    token = secrets.token_urlsafe(32)
    token_hash = hash_session_token(token)
    now = now_utc()
    expires_at = iso_utc(now + timedelta(seconds=SESSION_ABSOLUTE_TIMEOUT_SECONDS))
    session_id = str(uuid.uuid4())
    cur.execute(
        """
        INSERT INTO sessions (id, user_id, household_id, session_token_hash, expires_at, created_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            user["id"],
            family["id"],
            token_hash,
            expires_at,
            iso_utc(now),
            iso_utc(now),
        ),
    )
    con.commit()
    con.close()
    reset_rate_limit(ip, email)
    reset_lockout(ip, email)

    response.set_cookie(
        key=get_session_cookie_name(),
        value=token,
        httponly=True,
        samesite="lax",
        secure=ANNAFINDER_ENV == "prod",
        max_age=SESSION_ABSOLUTE_TIMEOUT_SECONDS,
        path="/",
    )
    ensure_csrf_cookie(request, response, rotate=True)

    ctx = build_security_context(request, {"user_id": user["id"], "family_id": family["id"]})
    emit_event(
        {
            **ctx,
            "event": "AUTH_LOGIN_SUCCESS",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/login"},
            "meta": {"email_hash": safe_hash(user["email"])},
        }
    )

    cur = db().cursor()
    cur.execute("SELECT email_verified_at FROM users WHERE id = ?", (user["id"],))
    verified_row = cur.fetchone()
    verified = bool(verified_row and verified_row["email_verified_at"])
    cur.connection.close()

    return {
        "ok": True,
        "user": {"email": user["email"], "email_verified": verified},
        "family": {"id": family["id"], "name": family["name"]},
    }


@app.post("/auth/logout")
def logout(request: Request, response: Response) -> Dict[str, Any]:
    session = get_session_from_cookie(request)
    token = request.cookies.get(get_session_cookie_name())
    if token:
        token_hash = hash_session_token(token)
        con = db()
        cur = con.cursor()
        cur.execute("DELETE FROM sessions WHERE session_token_hash = ?", (token_hash,))
        con.commit()
        con.close()
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "AUTH_LOGOUT",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/logout"},
        }
    )
    response.delete_cookie(key=get_session_cookie_name(), path="/")
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/auth/me")
def auth_me(
    response: Response, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT id, name, profile_complete FROM households WHERE id = ?",
        (session["household_id"],),
    )
    household = cur.fetchone()
    con.close()
    ensure_csrf_cookie(request, response, rotate=False)
    role = get_member_role(session["user_id"], session["household_id"])
    return {
        "ok": True,
        "user": {
            "email": session["email"],
            "role": role,
            "email_verified": bool(session.get("email_verified_at")),
        },
        "household": (
            {
                "id": household["id"],
                "name": household["name"],
                "profile_complete": bool(household["profile_complete"]),
            }
            if household
            else None
        ),
    }


@app.get("/auth/csrf")
def auth_csrf(request: Request, response: Response) -> Dict[str, Any]:
    require_allowed_origin(request)
    ensure_csrf_cookie(request, response, rotate=False)
    return {"ok": True}


@app.post("/household/invites/create")
def create_household_invite(
    data: InviteCreateInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_INVITE_CREATE, request)
    ip = request.client.host if request.client else None
    if not check_invite_rate(ip, data.email):
        ctx = build_security_context(request, session)
        emit_event(
            {
                **ctx,
                "event": "HOUSEHOLD_INVITE_CREATE",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/household/invites/create"},
                "meta": {"reason": "rate_limit", "email_hash": safe_hash(data.email)},
            }
        )
        raise HTTPException(status_code=429, detail="Too many requests, try again later")
    role = normalize_role(data.role)
    if role not in {ROLE_MEMBER, ROLE_VIEWER}:
        raise HTTPException(status_code=400, detail="Invalid role")

    invite_id, token = create_invite(
        session["household_id"], session["user_id"], role, mask_email(data.email)
    )
    lang = choose_lang(request)
    invite_link = f"{BASE_URL}/invite?token={token}"
    enqueue_email_template(
        "invite",
        lang,
        data.email,
        {
            "app_name": "AnnaFinder",
            "link": invite_link,
            "expires_days": str(7),
        },
        request.state.request_id,
        session["household_id"],
        session["user_id"],
    )
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "HOUSEHOLD_INVITE_CREATE",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/household/invites/create"},
            "meta": {"role": role, "email_hash": safe_hash(data.email)},
        }
    )
    emit_event(
        {
            **ctx,
            "event": "EMAIL_ENQUEUED",
            "severity": "LOW",
            "outcome": "SUCCESS",
            "target": {"resource": "email"},
            "meta": {"template": "invite"},
        }
    )

    if os.getenv("ANNAFINDER_INVITE_ECHO", "").lower() == "true":
        return {"ok": True, "invite_id": invite_id, "invite_link": invite_link}
    return {"ok": True, "invite_id": invite_id}


@app.get("/household/invites")
def list_household_invites(
    request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_INVITE_CREATE, request)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, created_at, expires_at, used_at, revoked_at, role_to_assign
        FROM household_invites
        WHERE household_id = ?
        ORDER BY created_at DESC
        """,
        (session["household_id"],),
    )
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return {"items": rows}


@app.post("/household/invites/accept")
def accept_household_invite(
    data: InviteAcceptInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_INVITE_ACCEPT, request)
    token = data.token.strip()
    invite = get_invite_by_token(token)
    if not invite:
        raise HTTPException(status_code=400, detail="Invalid invite")
    if invite["revoked_at"] or invite["used_at"]:
        raise HTTPException(status_code=400, detail="Invite not available")
    expires_at = parse_dt(invite["expires_at"])
    if not expires_at or expires_at < now_utc():
        raise HTTPException(status_code=400, detail="Invite expired")

    role = normalize_role(invite["role_to_assign"])
    if role not in {ROLE_MEMBER, ROLE_VIEWER, ROLE_OWNER}:
        raise HTTPException(status_code=400, detail="Invalid role")

    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id FROM household_members
        WHERE household_id = ? AND user_id = ?
        """,
        (invite["household_id"], session["user_id"]),
    )
    if not cur.fetchone():
        cur.execute(
            """
            INSERT INTO household_members (id, household_id, user_id, role, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                invite["household_id"],
                session["user_id"],
                role,
                iso_utc(now_utc()),
            ),
        )

    cur.execute(
        "UPDATE household_invites SET used_at = ? WHERE id = ?",
        (iso_utc(now_utc()), invite["id"]),
    )

    token_cookie = request.cookies.get(get_session_cookie_name())
    if token_cookie:
        cur.execute(
            "UPDATE sessions SET household_id = ? WHERE session_token_hash = ?",
            (invite["household_id"], hash_session_token(token_cookie)),
        )

    con.commit()
    con.close()

    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "HOUSEHOLD_INVITE_ACCEPT",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/household/invites/accept"},
            "meta": {"role": role},
        }
    )
    return {"ok": True, "household_id": invite["household_id"]}


@app.post("/household/invites/revoke")
def revoke_household_invite(
    data: InviteRevokeInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_INVITE_REVOKE, request)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id FROM household_invites
        WHERE id = ? AND household_id = ?
        """,
        (data.invite_id, session["household_id"]),
    )
    if not cur.fetchone():
        con.close()
        raise HTTPException(status_code=404, detail="Invite not found")
    cur.execute(
        "UPDATE household_invites SET revoked_at = ? WHERE id = ?",
        (iso_utc(now_utc()), data.invite_id),
    )
    con.commit()
    con.close()

    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "HOUSEHOLD_INVITE_REVOKE",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/household/invites/revoke"},
            "meta": {"invite_id": sanitize_str(data.invite_id, 64)},
        }
    )
    return {"ok": True}


@app.get("/household/members")
def list_household_members(
    request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_MEMBER_VIEW, request)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT u.id AS user_id, u.email AS email, hm.role, hm.created_at
        FROM household_members hm
        JOIN users u ON u.id = hm.user_id
        WHERE hm.household_id = ?
        ORDER BY hm.created_at ASC
        """,
        (session["household_id"],),
    )
    rows = []
    for r in cur.fetchall():
        rows.append(
            {
                "user_id": r["user_id"],
                "email": mask_email(r["email"]),
                "role": normalize_role(r["role"]),
                "created_at": r["created_at"],
            }
        )
    con.close()
    return {"items": rows}


@app.post("/household/profile/update")
def update_household_profile(
    data: HouseholdProfileInput,
    request: Request,
    session: Dict[str, Any] = Depends(require_session),
) -> Dict[str, Any]:
    require_permission(session, PERM_HOUSEHOLD_PROFILE_UPDATE, request)
    name = sanitize_str(data.name, HOUSEHOLD_NAME_MAX_LEN)
    if not name:
        return JSONResponse(status_code=400, content={"detail": "Name required"})
    con = db()
    cur = con.cursor()
    cur.execute(
        "UPDATE households SET name = ?, profile_complete = 1 WHERE id = ?",
        (name, session["household_id"]),
    )
    con.commit()
    con.close()
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "HOUSEHOLD_PROFILE_UPDATE",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/household/profile/update"},
        }
    )
    return {"ok": True}


@app.post("/household/members/role")
def change_member_role(
    data: MemberRoleInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_MEMBER_ROLE_CHANGE, request)
    role = normalize_role(data.role)
    if role not in {ROLE_OWNER, ROLE_MEMBER, ROLE_VIEWER}:
        raise HTTPException(status_code=400, detail="Invalid role")

    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT user_id, role FROM household_members
        WHERE household_id = ? AND user_id = ?
        """,
        (session["household_id"], data.member_user_id),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        raise HTTPException(status_code=404, detail="Member not found")

    current_role = normalize_role(row["role"])
    if (
        current_role == ROLE_OWNER
        and role != ROLE_OWNER
        and count_household_owners(session["household_id"]) <= 1
    ):
        con.close()
        raise HTTPException(status_code=400, detail="Cannot demote the last owner")

    cur.execute(
        "UPDATE household_members SET role = ? WHERE household_id = ? AND user_id = ?",
        (role, session["household_id"], data.member_user_id),
    )
    con.commit()
    con.close()

    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "HOUSEHOLD_ROLE_CHANGE",
            "severity": "MEDIUM",
            "outcome": "SUCCESS",
            "target": {"resource": "/household/members/role"},
            "meta": {"member_user_id": sanitize_str(data.member_user_id, 64), "role": role},
        }
    )
    return {"ok": True}


@app.post("/household/members/remove")
def remove_household_member(
    data: MemberRemoveInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_MEMBER_REMOVE, request)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT user_id, role FROM household_members
        WHERE household_id = ? AND user_id = ?
        """,
        (session["household_id"], data.member_user_id),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        raise HTTPException(status_code=404, detail="Member not found")

    current_role = normalize_role(row["role"])
    if current_role == ROLE_OWNER and count_household_owners(session["household_id"]) <= 1:
        con.close()
        raise HTTPException(status_code=400, detail="Cannot remove the last owner")

    cur.execute(
        "DELETE FROM household_members WHERE household_id = ? AND user_id = ?",
        (session["household_id"], data.member_user_id),
    )
    cur.execute(
        "DELETE FROM sessions WHERE household_id = ? AND user_id = ?",
        (session["household_id"], data.member_user_id),
    )
    con.commit()
    con.close()

    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "HOUSEHOLD_MEMBER_REMOVE",
            "severity": "HIGH",
            "outcome": "SUCCESS",
            "target": {"resource": "/household/members/remove"},
            "meta": {"member_user_id": sanitize_str(data.member_user_id, 64)},
        }
    )
    return {"ok": True}


@app.post("/auth/password/reset/request")
def password_reset_request(data: ResetRequestInput, request: Request) -> Dict[str, Any]:
    ip = request.client.host if request.client else None
    email = (data.email or "").strip().lower()
    if not check_reset_rate(ip, email):
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_PW_RESET_REQUEST",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/password/reset/request"},
                "meta": {"reason": "rate_limit", "email_hash": safe_hash(email)},
            }
        )
        return {"ok": True, "message": "If the account exists, a reset token will be issued."}

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cur.fetchone()
    token = ""
    if user:
        token = secrets.token_urlsafe(48)
        token_hash = safe_hash(token)
        cur.execute(
            """
            INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used_at, created_at, request_ip_hash)
            VALUES (?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                user["id"],
                token_hash,
                iso_utc(now_utc() + timedelta(seconds=RESET_TOKEN_TTL_SECONDS)),
                iso_utc(now_utc()),
                safe_hash(ip or ""),
            ),
        )
        con.commit()
    con.close()

    if user:
        lang = choose_lang(request)
        reset_link = f"{BASE_URL}/reset-password?token={token}"
        enqueue_email_template(
            "reset_request",
            lang,
            email,
            {
                "app_name": "AnnaFinder",
                "link": reset_link,
                "expires_minutes": str(int(RESET_TOKEN_TTL_SECONDS / 60)),
            },
            request.state.request_id,
            None,
            user["id"],
        )

    ctx = build_security_context(request, {"user_id": user["id"]} if user else None)
    emit_event(
        {
            **ctx,
            "event": "AUTH_PW_RESET_REQUEST",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/password/reset/request"},
            "meta": {"email_hash": safe_hash(data.email)},
        }
    )
    if user:
        emit_event(
            {
                **ctx,
                "event": "EMAIL_ENQUEUED",
                "severity": "LOW",
                "outcome": "SUCCESS",
                "target": {"resource": "email"},
                "meta": {"template": "reset_request"},
            }
        )

    if os.getenv("ANNAFINDER_RESET_TOKEN_ECHO", "").lower() == "true" and token:
        return {
            "ok": True,
            "message": "If the account exists, a reset token will be issued.",
            "reset_token": token,
        }
    return {"ok": True, "message": "If the account exists, a reset token will be issued."}


@app.post("/auth/password/reset/confirm")
def password_reset_confirm(data: ResetConfirmInput, request: Request) -> Dict[str, Any]:
    token_hash = safe_hash(data.token)
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, user_id, expires_at, used_at
        FROM password_reset_tokens
        WHERE token_hash = ?
        """,
        (token_hash,),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        ctx = build_security_context(request)
        emit_event(
            {
                **ctx,
                "event": "AUTH_PW_RESET_CONFIRM",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/password/reset/confirm"},
            }
        )
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired token"})

    expires = parse_dt(row["expires_at"])
    if row["used_at"] or (expires and expires < now_utc()):
        con.close()
        ctx = build_security_context(request, {"user_id": row["user_id"]})
        emit_event(
            {
                **ctx,
                "event": "AUTH_PW_RESET_CONFIRM",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/auth/password/reset/confirm"},
            }
        )
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired token"})

    new_hash = hash_password(data.new_password)
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, row["user_id"]))
    cur.execute(
        "UPDATE password_reset_tokens SET used_at = ? WHERE id = ?",
        (iso_utc(now_utc()), row["id"]),
    )
    cur.execute("DELETE FROM sessions WHERE user_id = ?", (row["user_id"],))
    cur.execute("SELECT email FROM users WHERE id = ?", (row["user_id"],))
    user_row = cur.fetchone()
    con.commit()
    con.close()

    ctx = build_security_context(request, {"user_id": row["user_id"]})
    emit_event(
        {
            **ctx,
            "event": "AUTH_PW_RESET_CONFIRM",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/auth/password/reset/confirm"},
        }
    )
    if user_row:
        lang = choose_lang(request)
        enqueue_email_template(
            "reset_done",
            lang,
            user_row["email"],
            {"app_name": "AnnaFinder"},
            request.state.request_id,
            None,
            row["user_id"],
        )
        emit_event(
            {
                **ctx,
                "event": "EMAIL_ENQUEUED",
                "severity": "LOW",
                "outcome": "SUCCESS",
                "target": {"resource": "email"},
                "meta": {"template": "reset_done"},
            }
        )
    return {"ok": True}


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "name": "AnnaFinder Backend",
        "version": app.version,
        "health": "/health",
        "dashboard": "/dashboard-data",
        "items": "/items",
        "routines": "/routines",
        "events": "/events",
        "export": "/events/export?format=csv",
    }


@app.get("/health")
def health() -> Dict[str, Any]:
    db_ok = True
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        con.close()
    except sqlite3.DatabaseError:
        db_ok = False

    return {
        "ok": db_ok,
        "env": ANNAFINDER_ENV,
        "db": "ok" if db_ok else "fail",
        "uptime_seconds": round(time.monotonic() - START_TIME, 2),
        "version": read_version(),
        "data_rights": {
            "export": True,
            "delete": True,
            "retention_cleanup": ANNAFINDER_ENV != "prod",
        },
    }


class HealthzResponse(BaseModel):
    status: str
    version: str


@app.get(
    "/healthz",
    response_model=HealthzResponse,
    summary="Service health check",
    description="Returns the current health and service version.",
    responses={
        200: {"description": "Service is healthy"},
        503: {"description": "Service is unhealthy (not implemented)"},
    },
)
def healthz() -> HealthzResponse:
    return HealthzResponse(status="ok", version=SERVICE_VERSION)


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request) -> str:
    if ANNAFINDER_ENV == "prod":
        raise HTTPException(status_code=404, detail="Metrics disabled in prod")
    if METRICS_TOKEN:
        supplied = request.headers.get("X-Metrics-Token", "")
        if not supplied or not hmac.compare_digest(supplied, METRICS_TOKEN):
            raise HTTPException(status_code=403, detail="Metrics token required")
    with _metrics_lock:
        total = _metrics["requests_total"]
        avg_latency = _metrics["latency_ms_sum"] / total if total else 0.0
        lines = [
            f"requests_total {total}",
            f"requests_by_status 2xx={_metrics['status_2xx']} 4xx={_metrics['status_4xx']} 5xx={_metrics['status_5xx']}",
            f"avg_latency_ms {round(avg_latency, 2)}",
        ]
    return "\n".join(lines) + "\n"


@app.get("/dashboard-data")
def dashboard_data(session: Dict[str, Any] = Depends(require_session)) -> Dict[str, Any]:
    con = db()
    cur = con.cursor()
    household_id = session["household_id"]

    cur.execute(
        """
        SELECT id, name, icon, location, battery, notes, updated_at
        FROM items
        WHERE household_id = ?
        ORDER BY name ASC
        """,
        (household_id,),
    )
    items = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT id, name, role
        FROM family_members
        WHERE household_id = ?
        ORDER BY created_at ASC
        """,
        (household_id,),
    )
    members = [dict(r) for r in cur.fetchall()]

    con.close()

    return {
        "profile": {
            "title": "AnnaFinder",
            "tagline": "Memory & belongings assistant (family-first)",
            "updated_at": iso_utc(now_utc()),
        },
        "items": items,
        "family_members": members,
        "role": get_member_role(session["user_id"], household_id),
    }


@app.get("/items")
def list_items(session: Dict[str, Any] = Depends(require_session)) -> Dict[str, Any]:
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, icon, location, battery, notes, updated_at
        FROM items
        WHERE household_id = ?
        ORDER BY name ASC
        """,
        (session["household_id"],),
    )
    items = [dict(r) for r in cur.fetchall()]
    con.close()
    return {"items": items}


@app.post("/items/add")
def add_item(
    data: AddItemInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_ITEM_CREATE, request)
    con = db()
    cur = con.cursor()

    item_id = str(uuid.uuid4())[:8]
    ts = iso_utc(now_utc())
    cur.execute(
        """
        INSERT INTO items (id, household_id, name, icon, location, battery, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            item_id,
            session["household_id"],
            data.name,
            data.icon,
            data.location,
            data.battery,
            data.notes,
            ts,
            ts,
        ),
    )
    con.commit()
    con.close()

    add_event(
        "item_added",
        "Item added",
        f"{data.name} -> Location={data.location}",
        household_id=session["household_id"],
    )
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "ITEM_ADD",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/items/add", "id": sanitize_str(item_id)},
        }
    )
    return {"ok": True, "item_id": item_id}


@app.post("/items/edit")
def edit_item(
    data: EditItemInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_ITEM_UPDATE, request)
    con = db()
    cur = con.cursor()

    cur.execute(
        "SELECT * FROM items WHERE id = ? AND household_id = ?",
        (data.item_id, session["household_id"]),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        return JSONResponse(status_code=404, content={"detail": "Item not found"})

    before = dict(row)

    name = data.name if data.name is not None else before["name"]
    icon = data.icon if data.icon is not None else before["icon"]
    location = data.location if data.location is not None else before["location"]
    battery = data.battery if data.battery is not None else before["battery"]
    notes = data.notes if data.notes is not None else before["notes"]

    ts = iso_utc(now_utc())
    cur.execute(
        """
        UPDATE items
        SET name = ?, icon = ?, location = ?, battery = ?, notes = ?, updated_at = ?
        WHERE id = ?
        """,
        (name, icon, location, battery, notes, ts, data.item_id),
    )
    con.commit()
    con.close()

    add_event(
        "item_edited",
        "Item edited",
        f"{before['name']} -> {name} | {before['location']} -> {location}",
        household_id=session["household_id"],
    )
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "ITEM_UPDATE",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/items/edit", "id": sanitize_str(data.item_id)},
        }
    )
    return {"ok": True}


@app.post("/items/move")
def move_item(
    data: MoveItemInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_ITEM_UPDATE, request)
    con = db()
    cur = con.cursor()

    cur.execute(
        "SELECT id, name, location FROM items WHERE id = ? AND household_id = ?",
        (data.item_id, session["household_id"]),
    )
    row = cur.fetchone()
    if not row:
        con.close()
        return JSONResponse(status_code=404, content={"detail": "Item not found"})

    from_loc = row["location"]
    ts = iso_utc(now_utc())

    cur.execute(
        """
        UPDATE items
        SET location = ?, updated_at = ?
        WHERE id = ?
        """,
        (data.to_location, ts, data.item_id),
    )
    con.commit()
    con.close()

    add_event(
        "item_moved",
        "Item moved",
        f"{row['name']} -> {from_loc} -> {data.to_location}",
        household_id=session["household_id"],
    )
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "ITEM_MOVE",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/items/move", "id": sanitize_str(data.item_id)},
        }
    )
    return {"ok": True}


@app.get("/routines")
def list_routines(session: Dict[str, Any] = Depends(require_session)) -> Dict[str, Any]:
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, name, items_csv, enabled, updated_at
        FROM routines
        WHERE household_id = ?
        ORDER BY name ASC
        """,
        (session["household_id"],),
    )
    routines = []
    for r in cur.fetchall():
        routines.append(
            {
                "id": r["id"],
                "name": r["name"],
                "items": [x.strip() for x in r["items_csv"].split(",") if x.strip()],
                "enabled": bool(r["enabled"]),
                "updated_at": r["updated_at"],
            }
        )
    con.close()
    return {"routines": routines}


@app.post("/events/clear")
def clear_timeline(
    request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_DATA_DELETE, request)
    con = db()
    cur = con.cursor()
    cur.execute(
        "UPDATE events SET archived = 1 WHERE archived = 0 AND household_id = ?",
        (session["household_id"],),
    )
    con.commit()
    con.close()

    add_event(
        "events_cleared",
        "Timeline archived",
        '{"note":"archived_by_user"}',
        household_id=session["household_id"],
    )
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "EVENT_ARCHIVE",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/events/clear"},
        }
    )
    return {"ok": True}


@app.get("/events")
def list_events(
    include_archives: bool = False,
    kinds: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0, le=100000),
    session: Dict[str, Any] = Depends(require_session),
) -> Dict[str, Any]:
    kind_list = split_csv(kinds)
    since_dt = parse_dt(since)
    until_dt = parse_dt(until)

    where = []
    params: List[Any] = []

    if not include_archives:
        where.append("archived = 0")

        where.append("family_id = ?")
        params.append(session.get("family_id") or session.get("household_id"))

    if kind_list:
        where.append(f"kind IN ({','.join(['?'] * len(kind_list))})")
        params.extend(kind_list)

    if since_dt:
        where.append("ts >= ?")
        params.append(iso_utc(since_dt))

    if until_dt:
        where.append("ts <= ?")
        params.append(iso_utc(until_dt))

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    con = db()
    cur = con.cursor()

    count_sql = "SELECT COUNT(*) AS c FROM events"
    if where_sql:
        count_sql += where_sql
    cur.execute(count_sql, params)
    total = cur.fetchone()["c"]

    query_sql = """
        SELECT id, ts, kind, message, details, actor_user_id AS actor, archived
        FROM events
    """
    if where_sql:
        query_sql += f"\n{where_sql}"
    query_sql += """
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
        """
    cur.execute(query_sql, params + [limit, offset])
    items = [dict(r) for r in cur.fetchall()]
    con.close()

    return {"items": items, "total": total, "limit": limit, "offset": offset}


def to_csv(rows: List[Dict[str, Any]]) -> str:
    out = io.StringIO()
    fieldnames = ["ts", "kind", "message", "details", "actor", "archived"]
    w = csv.DictWriter(out, fieldnames=fieldnames)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in fieldnames})
    return out.getvalue()


@app.get("/events/export")
def export_events(
    request: Request,
    format: str = Query("csv", pattern="^(csv|json)$"),
    include_archives: bool = False,
    kinds: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    session: Dict[str, Any] = Depends(require_session),
) -> Any:
    require_permission(session, PERM_DATA_EXPORT, request)
    kind_list = split_csv(kinds)
    since_dt = parse_dt(since)
    until_dt = parse_dt(until)

    where = []
    params: List[Any] = []

    if not include_archives:
        where.append("archived = 0")

    where.append("family_id = ?")
    params.append(session.get("family_id") or session.get("household_id"))

    if kind_list:
        where.append(f"kind IN ({','.join(['?'] * len(kind_list))})")
        params.extend(kind_list)

    if since_dt:
        where.append("ts >= ?")
        params.append(iso_utc(since_dt))

    if until_dt:
        where.append("ts <= ?")
        params.append(iso_utc(until_dt))

    where_sql = (" WHERE " + " AND ".join(where)) if where else ""

    con = db()
    cur = con.cursor()
    query_sql = """
        SELECT ts, kind, message, details, actor_user_id AS actor, archived
        FROM events
    """
    if where_sql:
        query_sql += f"\n{where_sql}"
    query_sql += """
        ORDER BY ts DESC
        """
    cur.execute(query_sql, params)
    rows = [dict(r) for r in cur.fetchall()]
    con.close()

    ts_tag = now_utc().strftime("%Y%m%d_%H%M%S")
    filename = f"annafinder_events_{ts_tag}.{format}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }

    if format == "json":
        payload = {"items": rows, "total": len(rows)}
        data = json.dumps(payload, ensure_ascii=True)
        return StreamingResponse(
            iter([data]), media_type="application/json; charset=utf-8", headers=headers
        )

    csv_text = to_csv(rows)
    return StreamingResponse(
        iter([csv_text]), media_type="text/csv; charset=utf-8", headers=headers
    )


@app.get("/data/export")
def export_data(
    request: Request,
    format: str = Query("json", pattern="^(json|zip)$"),
    session: Dict[str, Any] = Depends(require_session),
) -> Any:
    require_permission(session, PERM_DATA_EXPORT, request)
    payload = fetch_export_payload(session.get("family_id") or session["household_id"])
    meta = {
        "version": read_version(),
        "exported_at": iso_utc(now_utc()),
        "env": ANNAFINDER_ENV,
    }

    if format == "json":
        data = {"metadata": meta, **payload}
        body = json.dumps(data, ensure_ascii=True)
        headers = {
            "Content-Disposition": 'attachment; filename="annafinder_data.json"',
            "Cache-Control": "no-store",
        }
        ctx = build_security_context(request, session)
        emit_event(
            {
                **ctx,
                "event": "DATA_EXPORT",
                "severity": "INFO",
                "outcome": "SUCCESS",
                "target": {"resource": "/data/export"},
                "meta": {"format": sanitize_str(format)},
            }
        )
        return StreamingResponse(
            iter([body]), media_type="application/json; charset=utf-8", headers=headers
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("metadata.json", json.dumps(meta, ensure_ascii=True))
        zf.writestr("items.json", json.dumps(payload["items"], ensure_ascii=True))
        zf.writestr("events.json", json.dumps(payload["events"], ensure_ascii=True))
        zf.writestr("routines.json", json.dumps(payload["routines"], ensure_ascii=True))
        zf.writestr("family_members.json", json.dumps(payload["family_members"], ensure_ascii=True))
    buf.seek(0)
    headers = {
        "Content-Disposition": 'attachment; filename="annafinder_data.zip"',
        "Cache-Control": "no-store",
    }
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "DATA_EXPORT",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/data/export"},
            "meta": {"format": sanitize_str(format)},
        }
    )
    return StreamingResponse(buf, media_type="application/zip", headers=headers)


@app.post("/data/delete/request")
def request_delete(
    request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_DATA_DELETE, request)
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "DATA_DELETE_REQUEST",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/data/delete/request"},
        }
    )
    return issue_delete_token(session["household_id"])


@app.post("/data/delete/confirm")
def confirm_delete(
    data: DeleteConfirmInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_DATA_DELETE, request)
    if data.confirm_text != "DELETE":
        ctx = build_security_context(request, session)
        emit_event(
            {
                **ctx,
                "event": "DATA_DELETE_CONFIRM",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/data/delete/confirm"},
                "meta": {"reason": "confirm_text_mismatch"},
            }
        )
        return JSONResponse(status_code=400, content={"detail": "Confirm text mismatch"})
    if not consume_delete_token(data.delete_token, session["household_id"]):
        ctx = build_security_context(request, session)
        emit_event(
            {
                **ctx,
                "event": "DATA_DELETE_CONFIRM",
                "severity": "MEDIUM",
                "outcome": "FAIL",
                "target": {"resource": "/data/delete/confirm"},
                "meta": {"reason": "invalid_token"},
            }
        )
        return JSONResponse(status_code=400, content={"detail": "Invalid or expired delete token"})

    counts = clear_all_data(session["household_id"])
    add_event(
        "data_deleted",
        "User data deleted",
        json.dumps(counts, ensure_ascii=True),
        household_id=session["household_id"],
    )
    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "DATA_DELETE_CONFIRM",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/data/delete/confirm"},
            "meta": {"items_deleted": counts.get("items", 0)},
        }
    )
    return {"ok": True, "deleted": counts}


@app.post("/admin/retention/run")
def run_retention_cleanup(
    request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    if ANNAFINDER_ENV == "prod":
        return JSONResponse(status_code=404, content={"detail": "Not found"})

    cutoff_events = iso_utc(now_utc() - timedelta(days=RETENTION_EVENTS_DAYS))
    con = db()
    cur = con.cursor()
    cur.execute(
        "SELECT COUNT(*) AS c FROM events WHERE ts < ? AND household_id = ?",
        (cutoff_events, session["household_id"]),
    )
    events_to_delete = cur.fetchone()["c"]
    cur.execute(
        "DELETE FROM events WHERE ts < ? AND household_id = ?",
        (cutoff_events, session["household_id"]),
    )
    con.commit()
    con.close()

    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "RETENTION_RUN",
            "severity": "INFO",
            "outcome": "SUCCESS",
            "target": {"resource": "/admin/retention/run"},
            "meta": {"events_deleted": events_to_delete},
        }
    )
    return {
        "ok": True,
        "events_deleted": events_to_delete,
        "logs_deleted": 0,
        "policy_days": {"events": RETENTION_EVENTS_DAYS, "logs": RETENTION_LOGS_DAYS},
    }


@app.post("/feedback")
def submit_feedback(
    data: FeedbackInput, request: Request, session: Dict[str, Any] = Depends(require_session)
) -> Dict[str, Any]:
    require_permission(session, PERM_FEEDBACK_SUBMIT, request)
    page = sanitize_str(data.page, 120) or "unknown"
    message = sanitize_str(data.message, 1000)
    if not message:
        raise HTTPException(status_code=400, detail="Message required")

    rating = data.rating if data.rating in (1, 2, 3, 4, 5) else None
    created_at = iso_utc(now_utc())
    request_id = get_request_id(request)

    con = db()
    cur = con.cursor()
    cur.execute(
        """
        INSERT INTO feedback (id, household_id, user_id, page, rating, message, created_at, request_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            session["household_id"],
            session["user_id"],
            page,
            rating,
            message,
            created_at,
            request_id,
        ),
    )
    con.commit()
    con.close()

    ctx = build_security_context(request, session)
    emit_event(
        {
            **ctx,
            "event": "FEEDBACK_SUBMITTED",
            "severity": "LOW",
            "outcome": "SUCCESS",
            "target": {"resource": "/feedback"},
            "meta": {"page": page, "has_rating": bool(rating)},
        }
    )
    return {"ok": True}
