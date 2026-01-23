import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault("ANNAFINDER_ENV", "test")
from backend.main import app  # noqa: E402


def test_meta_endpoint_returns_versioned_payload() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/meta")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("api") == "v1"
    assert payload.get("service") == "AnnaFinder"


def test_validation_error_format_is_standardized() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/_test/validation")
    assert response.status_code == 422
    payload = response.json()
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    assert payload["error"]["message"] == "Invalid request"
    details = payload["error"]["details"]
    assert isinstance(details, list)
    assert details
    entry = details[0]
    assert "loc" in entry
    assert "msg" in entry
    assert "type" in entry
