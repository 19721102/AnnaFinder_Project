import os
import sys
import uuid
from pathlib import Path
from typing import Optional

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
    cur.execute("DROP TABLE IF EXISTS items")
    cur.execute("DROP TABLE IF EXISTS family_members")
    cur.execute("DROP TABLE IF EXISTS families")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS families (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS items (
            id TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            location_id TEXT,
            name TEXT NOT NULL,
            description TEXT,
            icon TEXT,
            battery INTEGER NOT NULL DEFAULT 100,
            notes TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute("DROP TABLE IF EXISTS events")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            actor_user_id TEXT,
            ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            archived INTEGER NOT NULL DEFAULT 0
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS item_tag_links (
            id TEXT PRIMARY KEY,
            item_id TEXT NOT NULL,
            tag_id TEXT NOT NULL,
            UNIQUE(item_id, tag_id)
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


def _create_location(client: TestClient, family_id: str, token: str, name: str) -> str:
    response = client.post(
        f"/api/v1/families/{family_id}/locations", json={"name": name}, headers=_auth_header(token)
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_item(
    client: TestClient,
    family_id: str,
    token: str,
    name: str,
    location_id: Optional[str] = None,
    description: Optional[str] = None,
) -> str:
    payload = {"name": name}
    if location_id:
        payload["location_id"] = location_id
    if description is not None:
        payload["description"] = description
    response = client.post(
        f"/api/v1/families/{family_id}/items", json=payload, headers=_auth_header(token)
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_items_crud_happy_path(client: TestClient) -> None:
    email = "items-owner@example.com"
    password = "ItemPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Item Family")
    _add_family_member(family_id, user_id, role="owner", is_owner=True)
    location_id = _create_location(client, family_id, token, "Kitchen")

    item_id = _create_item(
        client,
        family_id,
        token,
        "Fridge",
        location_id=location_id,
    )
    detail_resp = client.get(
        f"/api/v1/families/{family_id}/items/{item_id}", headers=_auth_header(token)
    )
    assert detail_resp.status_code == 200
    assert detail_resp.json()["location_id"] == location_id
    assert detail_resp.json()["status"] == "active"

    detail = client.get(
        f"/api/v1/families/{family_id}/items/{item_id}", headers=_auth_header(token)
    )
    assert detail.status_code == 200
    assert detail.json()["name"] == "Fridge"

    patch = client.patch(
        f"/api/v1/families/{family_id}/items/{item_id}",
        json={"name": "Freezer"},
        headers=_auth_header(token),
    )
    print("PATCH REQ", patch.status_code, patch.json())
    assert patch.status_code == 200
    assert patch.json()["name"] == "Freezer"

    delete = client.delete(
        f"/api/v1/families/{family_id}/items/{item_id}", headers=_auth_header(token)
    )
    assert delete.status_code == 204

    missing = client.get(
        f"/api/v1/families/{family_id}/items/{item_id}", headers=_auth_header(token)
    )
    assert missing.status_code == 404


def test_items_filters_pagination(client: TestClient) -> None:
    email = "items-filter@example.com"
    password = "FilterPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Filter Family")
    _add_family_member(family_id, user_id)
    location_a = _create_location(client, family_id, token, "Garage")
    location_b = _create_location(client, family_id, token, "Attic")

    for room in ["House", "Garage", "Attic"]:
        _create_item(
            client,
            family_id,
            token,
            room,
            location_id=location_a if room != "Attic" else location_b,
        )

    list_resp = client.get(
        f"/api/v1/families/{family_id}/items?location_id={location_a}", headers=_auth_header(token)
    )
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2

    q_resp = client.get(
        f"/api/v1/families/{family_id}/items?q=attic", headers=_auth_header(token)
    )
    assert q_resp.status_code == 200
    assert q_resp.json()["total"] == 1

    page_resp = client.get(
        f"/api/v1/families/{family_id}/items?limit=2&offset=1", headers=_auth_header(token)
    )
    assert page_resp.status_code == 200
    paged = page_resp.json()
    assert paged["offset"] == 1
    assert len(paged["items"]) == 2


def test_items_isolation_and_location_validation(client: TestClient) -> None:
    email = "items-tenant@example.com"
    password = "TenantPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_a = _create_family("Tenant Alpha")
    family_b = _create_family("Tenant Beta")
    _add_family_member(family_a, user_id)
    beta_email = "items-beta@example.com"
    beta_password = "BetaPass123!"
    _register_user(client, beta_email, beta_password)
    beta_token = _login_access_token(client, beta_email, beta_password)
    beta_user_id = _get_user_id(beta_email)
    _add_family_member(family_b, beta_user_id)
    beta_location = _create_location(client, family_b, beta_token, "Beta Room")
    other_item_id = _create_item(client, family_b, beta_token, "Secret", location_id=beta_location)

    resp = client.get(
        f"/api/v1/families/{family_b}/items/{other_item_id}", headers=_auth_header(token)
    )
    assert resp.status_code == 404
    error = resp.json()["error"]
    assert error["message"] == "Family not found or access denied"

    bad_location = _create_location(client, family_b, beta_token, "Beta Hangar")
    bad_resp = client.post(
        f"/api/v1/families/{family_a}/items",
        json={"name": "Sneaky", "location_id": bad_location},
        headers=_auth_header(token),
    )
    assert bad_resp.status_code == 404
    assert bad_resp.json()["error"]["message"] == "Family not found or access denied"


def test_items_validation_and_auth_errors(client: TestClient) -> None:
    family_id = _create_family("Solo Family")
    response = client.post(
        f"/api/v1/families/{family_id}/items",
        json={"name": ""},
    )
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "HTTP_ERROR"

    email = "items-validate@example.com"
    password = "ItemVal123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)
    _add_family_member(family_id, user_id)

    validation = client.post(
        f"/api/v1/families/{family_id}/items",
        json={"name": ""},
        headers=_auth_header(token),
    )
    assert validation.status_code == 422
    payload = validation.json()
    assert payload["error"]["code"] == "VALIDATION_ERROR"
