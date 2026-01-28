import uuid
from typing import Any

from fastapi.testclient import TestClient

from backend.main import app


def test_request_id_header_is_echoed() -> None:
    client = TestClient(app)
    unique_id = "trace-abc-123"
    response = client.get("/healthz", headers={"X-Request-Id": unique_id})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == unique_id


def test_request_id_generated_when_missing() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    uuid.UUID(response.headers["X-Request-Id"])


def test_error_report_sanitizes_sensitive_fields(monkeypatch) -> None:
    client = TestClient(app)
    payload = {"message": "boom", "password": "secret", "token": "abc123", "kind": "test"}
    captured: dict[str, dict[str, Any]] = {}

    def capture(level: Any, event: str, **fields: Any) -> None:
        captured["event"] = event
        captured["fields"] = fields

    monkeypatch.setattr("backend.api.v1.routes.observability.log_structured", capture)
    response = client.post(
        "/api/v1/error-report",
        headers={"X-Request-Id": "obs-trace-42"},
        json=payload,
    )
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "accepted"
    assert body["request_id"] == "obs-trace-42"

    assert captured, "log_structured should be called"
    assert captured["event"] == "error_report"
    assert captured["fields"]["payload"]["password"] == "<redacted>"
    assert captured["fields"]["payload"]["token"] == "<redacted>"
