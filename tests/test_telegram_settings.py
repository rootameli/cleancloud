import types
from fastapi.testclient import TestClient

from app.main import app
from app.api import settings as settings_api
from app.core.auth import get_current_user


def override_user():
    return {"sub": "tester"}


def test_save_and_get_telegram_settings(monkeypatch, tmp_path):
    app.dependency_overrides[get_current_user] = override_user
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(settings_api, "SETTINGS_FILE", settings_file)

    client = TestClient(app)

    payload = {"bot_token": "123456789:TESTTOKEN", "chat_id": "-1", "enabled": True}
    response = client.post("/api/v1/settings/telegram", json=payload, headers={"Authorization": "Bearer token"})
    assert response.status_code == 200
    masked = response.json()["settings"]["bot_token"]
    assert "*" in masked and masked.startswith("1234")

    response = client.get("/api/v1/settings/telegram", headers={"Authorization": "Bearer token"})
    assert response.status_code == 200
    data = response.json()
    assert data["enabled"] is True
    assert data["bot_token"].startswith("1234")

    app.dependency_overrides.clear()


def test_telegram_test_notification(monkeypatch, tmp_path):
    app.dependency_overrides[get_current_user] = override_user
    settings_file = tmp_path / "settings.json"
    monkeypatch.setattr(settings_api, "SETTINGS_FILE", settings_file)

    # Seed settings file
    settings_api._save_settings({
        "telegram": {"bot_token": "token", "chat_id": "123", "enabled": True}
    })

    class DummyResponse:
        status_code = 200

        def json(self):
            return {"ok": True}

    class DummyAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return DummyResponse()

    httpx_stub = types.SimpleNamespace(AsyncClient=DummyAsyncClient)
    monkeypatch.setattr(settings_api, "httpx", httpx_stub)

    client = TestClient(app)
    response = client.post("/api/v1/notifications/test/telegram", headers={"Authorization": "Bearer token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("success") is True

    app.dependency_overrides.clear()
