from pathlib import Path
import os
import sys

from fastapi.testclient import TestClient

os.environ.setdefault("ANNAFINDER_ENV", "test")
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

import backend.main as backend_main  # noqa: E402
from backend.main import CSRF_COOKIE_NAME, app  # noqa: E402

WILDCARD_HOST = ".".join(["0"] * 4)


def _fetch_csrf_token(client: TestClient, origin: str) -> str:
    response = client.get("/auth/csrf", headers={"Origin": origin})
    assert response.status_code == 200
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token
    return token


def _login_demo(client: TestClient, origin: str) -> None:
    token = _fetch_csrf_token(client, origin)
    response = client.post(
        "/auth/login",
        json={"email": "demo@annafinder.local", "password": "Demo1234!"},
        headers={"Origin": origin, "X-CSRF-Token": token},
    )
    assert response.status_code == 200


def test_events_list_filters_by_kind():
    allowed_origin = backend_main.get_allowed_origins()[0]
    backend_main.reset_db()
    with TestClient(app) as client:
        _login_demo(client, allowed_origin)
        response = client.get("/events?kinds=seed&limit=2", headers={"Origin": allowed_origin})
    assert response.status_code == 200
    payload = response.json()
    assert payload["limit"] == 2
    assert payload["offset"] == 0
    assert payload["total"] >= len(payload["items"])
    assert payload["items"]
    assert all(item["kind"] == "seed" for item in payload["items"])


def test_trusted_hosts_removes_wildcard():
    assert WILDCARD_HOST not in backend_main.TRUSTED_HOSTS
