import json
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
    cur.execute("DROP TABLE IF EXISTS events")
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


def _create_tag(client: TestClient, family_id: str, token: str, name: str) -> str:
    response = client.post(
        f"/api/v1/families/{family_id}/tags", json={"name": name}, headers=_auth_header(token)
    )
    assert response.status_code == 201
    return response.json()["id"]


def _fetch_events() -> list[dict]:
    con = db()
    cur = con.cursor()
    cur.execute(
        """
        SELECT id, kind, message, details, actor_user_id, ts
        FROM events
        ORDER BY ts ASC
        """
    )
    rows = [dict(r) for r in cur.fetchall()]
    con.close()
    return rows


def test_events_emit_and_filters(client: TestClient) -> None:
    email = "events-owner@example.com"
    password = "EventPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Event Family")
    _add_family_member(family_id, user_id, role="owner", is_owner=True)
    location_a = _create_location(client, family_id, token, "Storage")
    location_b = _create_location(client, family_id, token, "Garage")

    item_id = _create_item(client, family_id, token, "Backpack", location_id=location_a)
    assert _fetch_events()[-1]["kind"] == "item.created"

    patch = client.patch(
        f"/api/v1/families/{family_id}/items/{item_id}",
        json={"name": "Travel Pack"},
        headers=_auth_header(token),
    )
    assert patch.status_code == 200
    patch_location = client.patch(
        f"/api/v1/families/{family_id}/items/{item_id}",
        json={"location_id": location_b},
        headers=_auth_header(token),
    )
    assert patch_location.status_code == 200

    tag_id = _create_tag(client, family_id, token, "Essentials")
    link_resp = client.post(
        f"/api/v1/families/{family_id}/items/{item_id}/tags/{tag_id}",
        headers=_auth_header(token),
    )
    assert link_resp.status_code == 200

    unlink_resp = client.delete(
        f"/api/v1/families/{family_id}/items/{item_id}/tags/{tag_id}",
        headers=_auth_header(token),
    )
    assert unlink_resp.status_code == 204

    events = _fetch_events()
    kinds = [entry["kind"] for entry in events]
    assert "item.created" in kinds
    assert kinds.count("item.updated") >= 2
    assert "item.moved" in kinds
    assert "tag.linked" in kinds
    assert "tag.unlinked" in kinds

    moved_event = next(entry for entry in events if entry["kind"] == "item.moved")
    moved_payload = json.loads(moved_event["details"])
    assert moved_payload["from_location_id"] == location_a
    assert moved_payload["to_location_id"] == location_b
    assert moved_payload["fields_changed"] == ["location_id"]

    resp = client.get(
        f"/api/v1/families/{family_id}/events?type=item.moved", headers=_auth_header(token)
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["kind"] == "item.moved"
    assert data["items"][0]["payload"]["item_id"] == item_id

    resp_by_item = client.get(
        f"/api/v1/families/{family_id}/events?item_id={item_id}", headers=_auth_header(token)
    )
    assert resp_by_item.status_code == 200
    assert resp_by_item.json()["total"] >= 4
    assert all(event["payload"].get("item_id") == item_id for event in resp_by_item.json()["items"])

    paged = client.get(
        f"/api/v1/families/{family_id}/events?limit=2&offset=1", headers=_auth_header(token)
    )
    assert paged.status_code == 200
    paged_data = paged.json()
    assert paged_data["limit"] == 2
    assert paged_data["offset"] == 1
    assert len(paged_data["items"]) == 2


def test_events_errors_and_access_controls(client: TestClient) -> None:
    email = "events-guest@example.com"
    password = "GuestPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Secure Family")
    _add_family_member(family_id, user_id)
    location_id = _create_location(client, family_id, token, "Hall")
    _create_item(client, family_id, token, "Journal", location_id=location_id)

    unauthorized = client.get(f"/api/v1/families/{family_id}/events")
    assert unauthorized.status_code == 401
    assert unauthorized.json()["error"]["code"] == "HTTP_ERROR"

    other_family = _create_family("Other House")
    forbidden = client.get(
        f"/api/v1/families/{other_family}/events", headers=_auth_header(token)
    )
    assert forbidden.status_code == 404
    assert forbidden.json()["error"]["code"] == "HTTP_ERROR"

    invalid_limit = client.get(
        f"/api/v1/families/{family_id}/events?limit=0", headers=_auth_header(token)
    )
    assert invalid_limit.status_code == 422
    assert invalid_limit.json()["error"]["code"] == "VALIDATION_ERROR"

    missing_item = client.get(
        f"/api/v1/families/{family_id}/events?item_id={uuid.uuid4()}",
        headers=_auth_header(token),
    )
    assert missing_item.status_code == 404
    assert missing_item.json()["error"]["code"] == "HTTP_ERROR"
