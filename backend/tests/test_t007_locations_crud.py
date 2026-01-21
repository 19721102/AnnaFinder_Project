import os
import sys
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("ANNAFINDER_ENV", "test")
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

import backend.main as backend_main  # noqa: E402
from backend.main import app, db, iso_utc, now_utc  # noqa: E402


@pytest.fixture(autouse=True)
def reset_state():
    backend_main.reset_db()
    yield


@pytest.fixture(autouse=True)
def ensure_family_schema(reset_state):
    con = db()
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS locations")
    cur.execute("DROP TABLE IF EXISTS family_members")
    cur.execute("DROP TABLE IF EXISTS families")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS families (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS family_members (
            id TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            role TEXT NOT NULL,
            is_owner INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(family_id, user_id)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS locations (
            id TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            icon TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    con.commit()
    con.close()
    yield


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _csrf_headers(client: TestClient, token: str) -> dict[str, str]:
    csrf_token = client.cookies.get("anna_csrf")
    if not csrf_token:
        client.get("/healthz")
        csrf_token = client.cookies.get("anna_csrf")
    headers = _auth_header(token)
    headers["X-CSRF-Token"] = csrf_token or ""
    headers["Origin"] = "http://localhost:3000"
    return headers


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
    assert row, f"User {email} missing"
    return row["id"]


def _create_family(name: str) -> str:
    con = db()
    cur = con.cursor()
    family_id = str(uuid.uuid4())
    ts = iso_utc(now_utc())
    cur.execute(
        """
        INSERT INTO families (id, name, description, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (family_id, name, None, ts, ts),
    )
    con.commit()
    con.close()
    return family_id


def _add_family_member(family_id: str, user_id: str, role: str = "member", is_owner: bool = False) -> str:
    con = db()
    cur = con.cursor()
    membership_id = str(uuid.uuid4())
    ts = iso_utc(now_utc())
    cur.execute(
        """
        INSERT INTO family_members (id, family_id, user_id, role, is_owner, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (membership_id, family_id, user_id, role, int(bool(is_owner)), ts, ts),
    )
    con.commit()
    con.close()
    return membership_id


def _insert_location(family_id: str, name: str) -> str:
    con = db()
    cur = con.cursor()
    location_id = str(uuid.uuid4())
    ts = iso_utc(now_utc())
    cur.execute(
        """
        INSERT INTO locations (id, family_id, name, description, icon, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (location_id, family_id, name, None, None, ts, ts),
    )
    con.commit()
    con.close()
    return location_id


def test_locations_crud_happy_path(client: TestClient) -> None:
    email = "locations-owner@example.com"
    password = "LocPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Home Base")
    _add_family_member(family_id, user_id, role="owner", is_owner=True)

    create_payload = {"name": "Living Room", "description": "Cozy", "icon": "LR"}
    response = client.post(
        f"/api/v1/families/{family_id}/locations",
        json=create_payload,
        headers=_csrf_headers(client, token),
    )
    assert response.status_code == 201
    created = response.json()
    location_id = created["id"]
    assert created["name"] == create_payload["name"]

    list_resp = client.get(
        f"/api/v1/families/{family_id}/locations", headers=_auth_header(token)
    )
    assert list_resp.status_code == 200
    list_payload = list_resp.json()
    assert list_payload["total"] == 1
    assert list_payload["limit"] == 50
    assert list_payload["offset"] == 0
    assert list_payload["items"][0]["id"] == location_id

    detail_resp = client.get(
        f"/api/v1/families/{family_id}/locations/{location_id}", headers=_auth_header(token)
    )
    assert detail_resp.status_code == 200
    assert detail_resp.json()["name"] == create_payload["name"]

    patch_resp = client.patch(
        f"/api/v1/families/{family_id}/locations/{location_id}",
        json={"name": "Living Room Updated"},
        headers=_csrf_headers(client, token),
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["name"] == "Living Room Updated"

    delete_resp = client.delete(
        f"/api/v1/families/{family_id}/locations/{location_id}",
        headers=_csrf_headers(client, token),
    )
    assert delete_resp.status_code == 204

    missing_resp = client.get(
        f"/api/v1/families/{family_id}/locations/{location_id}", headers=_auth_header(token)
    )
    assert missing_resp.status_code == 404


def test_locations_pagination(client: TestClient) -> None:
    email = "locations-paginate@example.com"
    password = "LocPage123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Paginator")
    _add_family_member(family_id, user_id)

    for i in range(3):
        payload = {"name": f"Room {i}"}
        resp = client.post(
            f"/api/v1/families/{family_id}/locations",
            json=payload,
            headers=_csrf_headers(client, token),
        )
        assert resp.status_code == 201

    page_resp = client.get(
        f"/api/v1/families/{family_id}/locations?limit=2&offset=1", headers=_auth_header(token)
    )
    assert page_resp.status_code == 200
    data = page_resp.json()
    assert data["total"] == 3
    assert len(data["items"]) == 2


def test_locations_isolation_returns_404(client: TestClient) -> None:
    email = "locations-tenant@example.com"
    password = "LocTenant123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_a = _create_family("Alpha Family")
    family_b = _create_family("Beta Family")
    _add_family_member(family_a, user_id)

    location_b = _insert_location(family_b, "Beta Room")

    response = client.get(
        f"/api/v1/families/{family_b}/locations/{location_b}", headers=_auth_header(token)
    )
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "HTTP_ERROR"
    assert error["message"] == "Family not found or access denied"
