from fastapi.testclient import TestClient

from app.main import app
from app.api import endpoints_enhanced
from app.core.httpx_executor import httpx_executor


def test_readyz_returns_503_when_httpx_missing(monkeypatch):
    """Ready endpoint should fail fast when httpx CLI is missing or not executable."""

    # Force httpx health to report missing binary
    monkeypatch.setattr(httpx_executor, "check_httpx_health", lambda: (False, "httpx binary missing"))

    # Avoid unexpected external calls during the check
    monkeypatch.setattr(endpoints_enhanced, "get_redis", lambda: type("DummyRedis", (), {"is_healthy": staticmethod(lambda: False)})())

    client = TestClient(app)
    response = client.get("/api/v1/readyz")

    assert response.status_code == 503
    payload = response.json()
    assert payload["components"].get("httpx")


def test_readyz_returns_503_when_httpx_not_executable(monkeypatch, tmp_path):
    dummy_path = tmp_path / "httpx"
    dummy_path.write_text("echo test")

    # Ensure the path exists but is not executable
    monkeypatch.setenv("HTTPX_PATH", str(dummy_path))
    monkeypatch.setattr(httpx_executor, "httpx_path", str(dummy_path))

    # Avoid unexpected external calls during the check
    monkeypatch.setattr(endpoints_enhanced, "get_redis", lambda: type("DummyRedis", (), {"is_healthy": staticmethod(lambda: False)})())

    client = TestClient(app)
    response = client.get("/api/v1/readyz")

    assert response.status_code == 503
    payload = response.json()
    assert "not executable" in payload["components"].get("httpx", "")
