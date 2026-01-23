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
    assert row, f"User {email} not found"
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


def test_authorized_member_can_fetch_family_membership(client: TestClient) -> None:
    email = "tenant-member@example.com"
    password = "TenantPass123!"
    _register_user(client, email, password)
    token = _login_access_token(client, email, password)
    user_id = _get_user_id(email)

    family_id = _create_family("Tenant Alpha")
    _add_family_member(family_id, user_id, role="owner", is_owner=True)

    response = client.get(f"/api/v1/families/{family_id}/me", headers=_auth_header(token))
    assert response.status_code == 200
    payload = response.json()
    assert payload == {"family_id": family_id, "user_id": user_id, "role": "owner"}


def test_other_family_returns_not_found(client: TestClient) -> None:
    subject_email = "tenant-subject@example.com"
    subject_password = "TenantPass123!"
    peer_email = "tenant-peer@example.com"
    peer_password = "TenantPass123!"

    _register_user(client, subject_email, subject_password)
    _register_user(client, peer_email, peer_password)
    subject_token = _login_access_token(client, subject_email, subject_password)
    peer_id = _get_user_id(peer_email)

    family_a = _create_family("Tenant Alpha")
    family_b = _create_family("Tenant Beta")
    _add_family_member(family_a, _get_user_id(subject_email))
    _add_family_member(family_b, peer_id)

    response = client.get(f"/api/v1/families/{family_b}/me", headers=_auth_header(subject_token))
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "HTTP_ERROR"
    assert error["message"] == "Family not found or access denied"


def test_family_membership_requires_token(client: TestClient) -> None:
    family_id = _create_family("Tenant Orphan")
    response = client.get(f"/api/v1/families/{family_id}/me")
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "HTTP_ERROR"
    assert isinstance(error["message"], str)
