import http.cookies
import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typing import Optional

os.environ.setdefault("ANNAFINDER_ENV", "test")
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

import backend.main as backend_main  # noqa: E402
from backend.main import (  # noqa: E402
    CSRF_COOKIE_NAME,
    LOGIN_RATE_MAX_ATTEMPTS,
    app,
    ensure_column,
    get_session_cookie_name,
 )


def _load_cookies(response):
    cookie = http.cookies.SimpleCookie()
    headers = getattr(response.headers, "get_list", lambda name: [])("set-cookie")
    for chunk in headers or []:
        cookie.load(chunk)
    return cookie


def _fetch_csrf_token(client: TestClient, origin: str) -> str:
    response = client.get("/auth/csrf", headers={"Origin": origin})
    assert response.status_code == 200
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token
    return token


@pytest.fixture(autouse=True)
def reset_state():
    backend_main.reset_db()
    for ip in [None, "testclient"]:
        backend_main.reset_rate_limit(ip, "demo@annafinder.local")
        backend_main.reset_lockout(ip, "demo@annafinder.local")
    yield
    backend_main.reset_db()


def _login_demo(client: TestClient, origin: Optional[str] = None):
    allowed_origin = origin or backend_main.get_allowed_origins()[0]
    token = _fetch_csrf_token(client, allowed_origin)
    response = client.post(
        "/auth/login",
        json={"email": "demo@annafinder.local", "password": "Demo1234!"},
        headers={"Origin": allowed_origin, "X-CSRF-Token": token},
    )
    assert response.status_code == 200
    return response


def test_login_requires_origin():
    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            json={"email": "demo@annafinder.local", "password": "Demo1234!"},
        )
    assert response.status_code == 403


def test_login_requires_csrf_token():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/login",
            json={"email": "demo@annafinder.local", "password": "Demo1234!"},
            headers={"Origin": allowed_origin},
        )
    assert response.status_code == 403


def test_session_cookie_has_secure_flags_in_prod(monkeypatch):
    monkeypatch.setattr(backend_main, "ANNAFINDER_ENV", "prod")
    with TestClient(app, base_url="https://testserver") as client:
        response = _login_demo(client)
    cookie = _load_cookies(response)[get_session_cookie_name()]
    assert str(cookie.get("httponly")).lower() == "true"
    assert str(cookie.get("secure")).lower() == "true"
    assert cookie.get("samesite").lower() == "lax"
    assert cookie.get("path") == "/"


def test_csrf_blocks_mutations_without_token():
    with TestClient(app) as client:
        _login_demo(client)
        origin = backend_main.get_allowed_origins()[0]
        probe = client.post(
            "/household/invites/create",
            json={"role": "member", "email": "csrf-block@example.com"},
            headers={"Origin": origin},
        )
    assert probe.status_code == 403
    assert probe.json().get("detail") == "CSRF failed"


def test_csrf_allows_mutations_with_token():
    with TestClient(app) as client:
        _login_demo(client)
        csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
        origin = backend_main.get_allowed_origins()[0]
        response = client.post(
            "/household/invites/create",
            json={"role": "member", "email": "csrf-allow@example.com"},
            headers={"X-CSRF-Token": csrf_token, "Origin": origin},
        )
    assert response.status_code == 200
    assert response.json().get("ok") is True


def test_cors_allows_and_blocks_origins():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        allow_response = client.get("/metrics", headers={"Origin": allowed_origin})
        assert allow_response.headers.get("access-control-allow-origin") == allowed_origin
        assert allow_response.headers.get("access-control-allow-credentials") == "true"
        blocked_response = client.get("/metrics", headers={"Origin": "https://evil.local"})
        assert blocked_response.headers.get("access-control-allow-origin") is None


def test_trusted_host_blocks_bad_host():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        _fetch_csrf_token(client, allowed_origin)
        response = client.get("/healthz", headers={"Host": "evil.example"})
    assert response.status_code == 400


def test_login_rate_limit_enforces_threshold():
    email = "demo@annafinder.local"
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        for _ in range(LOGIN_RATE_MAX_ATTEMPTS):
            token = _fetch_csrf_token(client, allowed_origin)
            attempt = client.post(
                "/auth/login",
                json={"email": email, "password": "BadPass123!"},
                headers={"Origin": allowed_origin, "X-CSRF-Token": token},
            )
            assert attempt.status_code == 401
        token = _fetch_csrf_token(client, allowed_origin)
        blocked = client.post(
            "/auth/login",
            json={"email": email, "password": "BadPass123!"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": token},
        )
    assert blocked.status_code == 429
    assert "Too many attempts" in blocked.json().get("detail", "")


def test_login_csrf_blocks_cross_origin():
    origin = "https://evil.example"
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/login",
            json={"email": "demo@annafinder.local", "password": "Demo1234!"},
            headers={"Origin": origin, "X-CSRF-Token": token},
        )
    assert response.status_code == 403


def test_login_allows_allowed_origin():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        response = _login_demo(client, origin=allowed_origin)
    assert response.status_code == 200


def test_register_csrf_blocks_cross_origin():
    origin = "https://evil.example"
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, backend_main.get_allowed_origins()[0])
        response = client.post(
            "/auth/register",
            json={"email": "new@user.local", "password": "Demo1234!", "household_name": "Test"},
            headers={"Origin": origin, "X-CSRF-Token": token},
        )
    assert response.status_code == 403


def test_register_requires_origin():
    with TestClient(app) as client:
        response = client.post(
            "/auth/register",
            json={"email": "new@user.local", "password": "Demo1234!", "household_name": "Test"},
        )
    assert response.status_code == 403


def test_register_requires_csrf_token():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/register",
            json={"email": "new@user.local", "password": "Demo1234!", "household_name": "Test"},
            headers={"Origin": allowed_origin},
        )
    assert response.status_code == 403


def test_password_reset_request_allows_guest_with_csrf():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/password/reset/request",
            json={"email": "demo@annafinder.local"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": token},
        )
    assert response.status_code == 200
    assert response.json().get("ok") is True


def test_password_reset_confirm_allows_guest_with_csrf(monkeypatch):
    monkeypatch.setenv("ANNAFINDER_RESET_TOKEN_ECHO", "true")
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, allowed_origin)
        request_resp = client.post(
            "/auth/password/reset/request",
            json={"email": "demo@annafinder.local"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": token},
        )
        assert request_resp.status_code == 200
        reset_token = request_resp.json().get("reset_token")
        assert reset_token
        confirm_resp = client.post(
            "/auth/password/reset/confirm",
            json={"token": reset_token, "new_password": "NewPass123!"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": token},
        )
    assert confirm_resp.status_code == 200
    assert confirm_resp.json() == {"ok": True}


def test_password_reset_request_blocks_missing_origin():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/password/reset/request",
            json={"email": "demo@annafinder.local"},
            headers={"X-CSRF-Token": token},
        )
    assert response.status_code == 403
    assert response.json().get("detail") == "CSRF origin failed"


def test_password_reset_request_blocks_disallowed_origin():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/password/reset/request",
            json={"email": "demo@annafinder.local"},
            headers={"Origin": "https://evil.local", "X-CSRF-Token": token},
        )
    assert response.status_code == 403
    assert response.json().get("detail") == "CSRF origin failed"


def test_password_reset_request_blocks_csrf_mismatch():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/password/reset/request",
            json={"email": "demo@annafinder.local"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": "invalid"},
        )
    assert response.status_code == 403
    assert response.json().get("detail") == "CSRF failed"


def test_verify_email_resend_allows_guest_with_csrf():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        token = _fetch_csrf_token(client, allowed_origin)
        response = client.post(
            "/auth/verify-email/resend",
            json={"email": "demo@annafinder.local"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": token},
        )
    assert response.status_code == 200
def test_state_change_requires_csrf_token():
    allowed_origin = backend_main.get_allowed_origins()[0]
    with TestClient(app) as client:
        _login_demo(client)
        token = client.cookies.get(CSRF_COOKIE_NAME)
        bad_response = client.post(
            "/household/invites/create",
            json={"role": "member", "email": "mismatch@example.com"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": "invalid"},
        )
        assert bad_response.status_code == 403
        assert bad_response.json().get("detail") == "CSRF failed"
        good_response = client.post(
            "/household/invites/create",
            json={"role": "member", "email": "valid@example.com"},
            headers={"Origin": allowed_origin, "X-CSRF-Token": token},
        )
        assert good_response.status_code == 200


def test_ensure_column_rejects_invalid_identifier():
    con = backend_main.db()
    with pytest.raises(ValueError):
        ensure_column(con, "users; DROP TABLE users", "col", "TEXT")
    ensure_column(con, "users", "extra_flag", "INTEGER")
    con.close()
