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
from backend.main import app, db  # noqa: E402


@pytest.fixture(autouse=True)
def reset_state():
    backend_main.reset_db()
    yield


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _register_user(client: TestClient, email: str, password: str) -> None:
    response = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201


def _login_access_token(client: TestClient, email: str, password: str) -> str:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def _get_user_id(email: str) -> str:
    con = db()
    cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE email = ?", (email.lower(),))
    row = cur.fetchone()
    con.close()
    assert row
    return row["id"]


def _assert_error_code(response, expected_code: str):
    body = response.json()
    assert "error" in body and body["error"]["code"] == expected_code


def _create_family(client: TestClient, token: str, name: str) -> str:
    response = client.post("/api/v1/families", json={"name": name}, headers=_auth_header(token))
    assert response.status_code == 201
    return response.json()["family_id"]


def test_unauthorized_rejected(client: TestClient):
    response = client.post("/api/v1/families", json={"name": "Unauth"})
    assert response.status_code == 401
    _assert_error_code(response, "HTTP_ERROR")


def test_create_list_detail_family(client: TestClient):
    email = "bootstrap@example.com"
    password = "Bootstrap123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    family_id = _create_family(client, token, "Founders")

    list_response = client.get("/api/v1/families", headers=_auth_header(token))
    assert list_response.status_code == 200
    families = list_response.json()["families"]
    assert any(f["family_id"] == family_id for f in families)

    detail = client.get(f"/api/v1/families/{family_id}", headers=_auth_header(token))
    assert detail.status_code == 200
    assert detail.json()["family_id"] == family_id
    assert detail.json()["name"] == "Founders"

    con = db()
    cur = con.cursor()
    cur.execute("SELECT family_id, user_id, role FROM family_members WHERE family_id = ?", (family_id,))
    membership = cur.fetchone()
    con.close()
    assert membership
    assert membership["role"] == "owner"


def test_cross_family_isolation(client: TestClient):
    owner_email = "owner@example.com"
    owner_password = "Owner123!"
    _register_user(client, owner_email, owner_password)
    owner_token = _login_access_token(client, owner_email, owner_password)
    family_id = _create_family(client, owner_token, "SharedHouse")

    guest_email = "guest@example.com"
    guest_password = "Guest123!"
    _register_user(client, guest_email, guest_password)
    guest_token = _login_access_token(client, guest_email, guest_password)

    resp = client.get(f"/api/v1/families/{family_id}", headers=_auth_header(guest_token))
    assert resp.status_code == 404
    _assert_error_code(resp, "HTTP_ERROR")


def test_validation_error_name(client: TestClient):
    email = "validate@example.com"
    password = "Validate123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    response = client.post("/api/v1/families", json={"name": ""}, headers=_auth_header(token))
    assert response.status_code == 422
    _assert_error_code(response, "VALIDATION_ERROR")
