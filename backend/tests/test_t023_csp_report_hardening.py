from fastapi.testclient import TestClient

from backend.api.v1.routes.csp_report import MAX_BYTES
from backend.main import app


def test_csp_report_accepts_valid_json() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=b'{"document-uri":"https://example.com"}',
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 204


def test_csp_report_rejects_invalid_content_type() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=b"{}",
            headers={"Content-Type": "application/xml"},
        )
    assert response.status_code == 415


def test_csp_report_payload_too_large() -> None:
    payload = b"x" * (MAX_BYTES + 1)
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=payload,
            headers={"Content-Type": "text/plain"},
        )
    assert response.status_code == 413


def test_csp_report_invalid_json_returns_204() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/csp-report",
            data=b"{",
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 204
