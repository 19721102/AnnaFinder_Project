import json

import pytest
from fastapi.testclient import TestClient

from backend.main import (
    CSP_REPORT_RATE_LIMIT,
    app,
    _reset_csp_rate_limits,
)


def _post_csp_report(client: TestClient, data: bytes, headers=None):
    headers = headers or {}
    headers.setdefault("Content-Type", "application/reports+json")
    return client.post("/__csp_report", data=data, headers=headers)


@pytest.fixture(autouse=True)
def clear_rate_limits():
    _reset_csp_rate_limits()
    yield


def test_csp_report_accepts_valid_request():
    with TestClient(app) as client:
        response = _post_csp_report(client, b'{"foo": "bar"}')
    assert response.status_code == 204


def test_csp_report_rejects_bad_content_type():
    with TestClient(app) as client:
        response = _post_csp_report(
            client,
            b"{}",
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 415


def test_csp_report_payload_too_large():
    with TestClient(app) as client:
        response = _post_csp_report(
            client,
            b"{}",
            headers={"Content-Type": "application/reports+json", "Content-Length": str(65537)},
        )
    assert response.status_code == 413


def test_csp_report_rate_limit():
    with TestClient(app) as client:
        for _ in range(CSP_REPORT_RATE_LIMIT):
            response = _post_csp_report(client, b"{}")
            assert response.status_code == 204
        response = _post_csp_report(client, b"{}")
    assert response.status_code == 429
