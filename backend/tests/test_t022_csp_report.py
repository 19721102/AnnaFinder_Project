from fastapi.testclient import TestClient

from backend import main


def test_csp_report_accepts_payload(monkeypatch) -> None:
    captured = {}
    payload = {
        "document-uri": "http://example.com/?secret=1",
        "blocked-uri": "http://evil.com",
        "violated-directive": "script-src",
        "extra": "should be dropped",
    }

    def capture(level, event, **fields):
        captured["event"] = event
        captured["fields"] = fields

    monkeypatch.setattr("backend.api.v1.routes.csp_report.log_structured", capture)
    client = TestClient(main.app)
    response = client.post("/api/v1/csp-report", json=payload)
    assert response.status_code == 204
    assert captured["event"] == "csp_report"
    assert captured["fields"]["payload"]["document-uri"] == "http://example.com/"


def test_csp_report_handles_invalid_json() -> None:
    client = TestClient(main.app)
    response = client.post(
        "/api/v1/csp-report",
        data="not json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 204
