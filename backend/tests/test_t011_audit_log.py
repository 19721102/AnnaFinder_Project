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
    cur.execute("DROP TABLE IF EXISTS audit_log")
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


def _assert_entry_type(entries: list[dict], expected_type: str) -> None:
    assert any(f"{entry['entity']}.{entry['action']}" == expected_type for entry in entries)


def test_audit_log_entries_and_filters(client: TestClient) -> None:
    email = "audit-owner@example.com"
    password = "AuditPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Audit Family")
    _add_family_member(family_id, user_id, role="owner", is_owner=True)
    location_id = _create_location(client, family_id, token, "Vault")
    item_id = _create_item(client, family_id, token, "Ledger", location_id=location_id)
    tag_id = _create_tag(client, family_id, token, "Important")

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

    resp = client.get(
        f"/api/v1/families/{family_id}/audit", headers=_auth_header(token)
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 4
    entries = data["audit"]
    _assert_entry_type(entries, "items.create")
    _assert_entry_type(entries, "tags.create")
    _assert_entry_type(entries, "item_tags.link")
    _assert_entry_type(entries, "item_tags.unlink")

    filtered = client.get(
        f"/api/v1/families/{family_id}/audit?type=items.create", headers=_auth_header(token)
    )
    assert filtered.status_code == 200
    filtered_data = filtered.json()
    assert filtered_data["total"] >= 1
    assert all(entry["entity"] == "items" for entry in filtered_data["audit"])

    actor_filter = client.get(
        f"/api/v1/families/{family_id}/audit?actor_user_id={user_id}",
        headers=_auth_header(token),
    )
    assert actor_filter.status_code == 200
    assert actor_filter.json()["total"] >= 3

    assert not any(
        "token" in json.dumps(entry.get("payload") or {}).lower()
        for entry in entries
    )

    other_family = _create_family("Other Audit")
    other_resp = client.get(
        f"/api/v1/families/{other_family}/audit", headers=_auth_header(token)
    )
    assert other_resp.status_code == 404
    assert other_resp.json()["error"]["code"] == "HTTP_ERROR"

    unauthorized = client.get(f"/api/v1/families/{family_id}/audit")
    assert unauthorized.status_code == 401
    assert unauthorized.json()["error"]["code"] == "HTTP_ERROR"
