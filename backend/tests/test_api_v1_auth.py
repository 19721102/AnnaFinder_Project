import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("ANNAFINDER_ENV", "test")
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

import backend.main as backend_main  # noqa: E402
from backend.main import app  # noqa: E402


@pytest.fixture(autouse=True)
def reset_state():
    backend_main.reset_db()
    yield


def test_register_success_creates_user_with_display_name():
    payload = {"email": "newuser@example.com", "password": "StrongPass123!", "display_name": "New User"}
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == payload["email"]
    assert data["display_name"] == payload["display_name"]
    assert "id" in data


def test_register_duplicate_email_is_conflict():
    payload = {"email": "demo@annafinder.local", "password": "Demo1234!"}
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 409
    error = response.json()["error"]
    assert error["code"] == "HTTP_ERROR"
    assert "Email already registered" in error["message"]


def test_login_returns_tokens_for_seed_user():
    payload = {"email": "demo@annafinder.local", "password": "Demo1234!"}
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["expires_in_sec"] > 0


def test_login_wrong_password_returns_401():
    payload = {"email": "demo@annafinder.local", "password": "WrongPass123!"}
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["message"] == "Invalid credentials"


def test_refresh_returns_new_tokens():
    login_payload = {"email": "demo@annafinder.local", "password": "Demo1234!"}
    with TestClient(app) as client:
        login_resp = client.post("/api/v1/auth/login", json=login_payload)
        refresh_resp = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": login_resp.json()["refresh_token"]}
        )
    assert refresh_resp.status_code == 200
    data = refresh_resp.json()
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "bearer"


def test_refresh_rejects_access_token():
    login_payload = {"email": "demo@annafinder.local", "password": "Demo1234!"}
    with TestClient(app) as client:
        login_resp = client.post("/api/v1/auth/login", json=login_payload)
        refresh_resp = client.post(
            "/api/v1/auth/refresh", json={"refresh_token": login_resp.json()["access_token"]}
        )
    assert refresh_resp.status_code == 401
    error = refresh_resp.json()["error"]
    assert error["message"] == "Invalid refresh token"
