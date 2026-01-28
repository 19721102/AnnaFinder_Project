from fastapi.testclient import TestClient

from backend.main import SERVICE_VERSION, app


def test_healthz_returns_status_and_version() -> None:
    client = TestClient(app)
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"] == SERVICE_VERSION


def test_openapi_includes_healthz_schema_and_tags() -> None:
    schema = app.openapi()
    healthz_path = schema["paths"]["/healthz"]["get"]
    assert healthz_path["summary"] == "Service health check"
    assert "HealthzResponse" in schema["components"]["schemas"]
    tags = {t["name"] for t in schema.get("tags", [])}
    assert {"meta", "auth", "observability"}.issubset(tags)
