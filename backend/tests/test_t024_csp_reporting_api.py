from fastapi.testclient import TestClient

from backend.api.v1.routes.csp_report import MAX_BYTES
from backend.main import app


def test_reporting_api_accepts_array_payload() -> None:
    payload = (
        b'[{"type":"csp-violation","body":{"document-uri":"https://example.com"}}]'
    )
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=payload,
            headers={"Content-Type": "application/reports+json"},
        )
    assert response.status_code == 204


def test_reporting_api_invalid_json_returns_204() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=b"{",
            headers={"Content-Type": "application/reports+json"},
        )
    assert response.status_code == 204


def test_reporting_api_rejects_bad_content_type() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=b"{}",
            headers={"Content-Type": "application/xml"},
        )
    assert response.status_code == 415


def test_reporting_api_payload_too_large() -> None:
    payload = b"x" * (MAX_BYTES + 1)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=payload,
            headers={"Content-Type": "application/reports+json"},
        )
    assert response.status_code == 413
