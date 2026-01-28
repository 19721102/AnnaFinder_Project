import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

from backend.main import app  # noqa: E402


def test_healthz_endpoint_is_open() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json().get("status") == "ok"


def test_healthz_includes_security_headers() -> None:
    with TestClient(app) as client:
        response = client.get("/healthz")
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert response.headers.get("x-frame-options") == "SAMEORIGIN"
    assert (
        response.headers.get("permissions-policy") == "geolocation=(), microphone=(), camera=()"
    )


def test_auth_login_sets_cache_control() -> None:
    payload = {"email": "demo@annafinder.local", "password": "Demo1234!"}
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    assert response.headers.get("cache-control") == "no-store"
