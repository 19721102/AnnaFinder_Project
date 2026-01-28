from fastapi.testclient import TestClient

from backend import main


def test_healthz_includes_security_headers() -> None:
    client = TestClient(main.app)
    response = client.get("/healthz")
    assert response.status_code == 200
    headers = response.headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["x-frame-options"] == "SAMEORIGIN"
    assert headers["permissions-policy"] == "geolocation=(), microphone=(), camera=()"
    assert "Strict-Transport-Security" not in headers


def test_hsts_only_on_prod_https(monkeypatch) -> None:
    monkeypatch.setattr(main, "APP_ENV", "prod")
    main.app.state.app_env = "prod"
    client = TestClient(main.app)
    response = client.get("/healthz", headers={"X-Forwarded-Proto": "https"})
    assert response.status_code == 200
    assert response.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
