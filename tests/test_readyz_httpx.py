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
