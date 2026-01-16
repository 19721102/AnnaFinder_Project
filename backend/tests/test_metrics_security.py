from fastapi.testclient import TestClient

import backend.main as backend_main
from backend.main import app


def test_metrics_disabled_in_prod(monkeypatch):
    monkeypatch.setenv("ANNAFINDER_ENV", "prod")
    monkeypatch.setattr(backend_main, "ANNAFINDER_ENV", "prod")
    monkeypatch.setattr(backend_main, "METRICS_TOKEN", "")
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 404


def test_metrics_requires_token_when_configured(monkeypatch):
    monkeypatch.setattr(backend_main, "ANNAFINDER_ENV", "dev")
    monkeypatch.setattr(backend_main, "METRICS_TOKEN", "secret-token")
    with TestClient(app) as client:
        missing = client.get("/metrics")
        wrong = client.get("/metrics", headers={"X-Metrics-Token": "wrong"})
        ok = client.get("/metrics", headers={"X-Metrics-Token": "secret-token"})
    assert missing.status_code == 403
    assert wrong.status_code == 403
    assert ok.status_code == 200
    assert "requests_total" in ok.text


def test_metrics_allows_access_without_token(monkeypatch):
    monkeypatch.setattr(backend_main, "ANNAFINDER_ENV", "dev")
    monkeypatch.setattr(backend_main, "METRICS_TOKEN", "")
    with TestClient(app) as client:
        response = client.get("/metrics")
    assert response.status_code == 200
    assert "requests_total" in response.text
