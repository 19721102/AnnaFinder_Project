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
def ensure_schema(reset_state):
    con = db()
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS item_tag_links")
    cur.execute("DROP TABLE IF EXISTS tags")
    cur.execute("DROP TABLE IF EXISTS items")
    cur.execute("DROP TABLE IF EXISTS locations")
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
        CREATE TABLE IF NOT EXISTS tags (
            id TEXT PRIMARY KEY,
            family_id TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(family_id, name)
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
) -> str:
    payload = {"name": name}
    if location_id:
        payload["location_id"] = location_id
    response = client.post(
        f"/api/v1/families/{family_id}/items", json=payload, headers=_auth_header(token)
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_tag(client: TestClient, family_id: str, token: str, name: str) -> str:
    response = client.post(
        f"/api/v1/families/{family_id}/tags", json={"name": name}, headers=_auth_header(token)
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_tags_crud_and_duplicate(client: TestClient) -> None:
    email = "tags-owner@example.com"
    password = "TagPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Tag Family")
    _add_family_member(family_id, user_id, role="owner", is_owner=True)

    tag_id = _create_tag(client, family_id, token, "Essentials")
    list_resp = client.get(f"/api/v1/families/{family_id}/tags", headers=_auth_header(token))
    assert list_resp.status_code == 200
    data = list_resp.json()
    assert len(data) == 1
    assert data[0]["id"] == tag_id

    dup = client.post(
        f"/api/v1/families/{family_id}/tags", json={"name": "Essentials"}, headers=_auth_header(token)
    )
    assert dup.status_code == 409
    assert dup.json()["error"]["message"] == "Tag already exists"

    delete_resp = client.delete(
        f"/api/v1/families/{family_id}/tags/{tag_id}", headers=_auth_header(token)
    )
    assert delete_resp.status_code == 204

    missing = client.delete(
        f"/api/v1/families/{family_id}/tags/{tag_id}", headers=_auth_header(token)
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "HTTP_ERROR"


def test_tags_validation_error(client: TestClient) -> None:
    email = "tags-validate@example.com"
    password = "ValTag123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)
    family_id = _create_family("Validation Family")
    _add_family_member(family_id, user_id)

    response = client.post(
        f"/api/v1/families/{family_id}/tags", json={"name": ""}, headers=_auth_header(token)
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert isinstance(error["details"], list)
    assert all("loc" in entry and "msg" in entry for entry in error["details"])


def test_item_tag_links_idempotent_and_isolation(client: TestClient) -> None:
    email = "tag-link@example.com"
    password = "LinkPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_a = _create_family("Alpha Tags")
    family_b = _create_family("Beta Tags")
    _add_family_member(family_a, user_id)

    beta_email = "tag-link-beta@example.com"
    beta_password = "BetaTag123!"
    _register_user(client, beta_email, beta_password)
    beta_token = _login_access_token(client, beta_email, beta_password)
    beta_user_id = _get_user_id(beta_email)
    _add_family_member(family_b, beta_user_id)

    location_id = _create_location(client, family_a, token, "Hall")
    item_id = _create_item(client, family_a, token, "Widget", location_id=location_id)
    tag_id = _create_tag(client, family_a, token, "Gadgets")

    link = client.post(
        f"/api/v1/families/{family_a}/items/{item_id}/tags/{tag_id}",
        headers=_auth_header(token),
    )
    assert link.status_code == 200
    assert link.json()["ok"]

    repeat = client.post(
        f"/api/v1/families/{family_a}/items/{item_id}/tags/{tag_id}",
        headers=_auth_header(token),
    )
    assert repeat.status_code == 200

    unlink = client.delete(
        f"/api/v1/families/{family_a}/items/{item_id}/tags/{tag_id}",
        headers=_auth_header(token),
    )
    assert unlink.status_code == 204

    unlink_again = client.delete(
        f"/api/v1/families/{family_a}/items/{item_id}/tags/{tag_id}",
        headers=_auth_header(token),
    )
    assert unlink_again.status_code == 204

    beta_tag = _create_tag(client, family_b, beta_token, "BetaTag")
    cross_link = client.post(
        f"/api/v1/families/{family_a}/items/{item_id}/tags/{beta_tag}",
        headers=_auth_header(token),
    )
    assert cross_link.status_code == 404
    cross_error = cross_link.json()["error"]
    assert cross_error["code"] == "HTTP_ERROR"

    cross_delete = client.delete(
        f"/api/v1/families/{family_a}/tags/{beta_tag}",
        headers=_auth_header(token),
    )
    assert cross_delete.status_code == 404
