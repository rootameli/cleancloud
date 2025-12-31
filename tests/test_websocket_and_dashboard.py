import sys
import types

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

# Provide a minimal jwt stub so importing the app does not require the external dependency
if "jwt" not in sys.modules:
    sys.modules["jwt"] = types.SimpleNamespace(
        encode=lambda payload, key, algorithm=None: "test-token",
        decode=lambda token, key, algorithms=None: {"sub": "stub"},
        ExpiredSignatureError=Exception,
        JWTError=Exception,
    )

from app.main import app
from app.core.auth import auth_manager, get_current_user
from app.core.database import get_db_session


class FakeResult:
    def __init__(self, scalar_value=None, fetchall_data=None):
        self.scalar_value = scalar_value
        self.fetchall_data = fetchall_data or []

    def scalar(self):
        return self.scalar_value

    def fetchall(self):
        return self.fetchall_data


class FakeSession:
    def __init__(self, results=None):
        self._results = list(results or [])

    async def execute(self, _query):
        if self._results:
            return self._results.pop(0)
        return FakeResult()


def override_current_user():
    return {"sub": "test-user"}


def test_dashboard_websocket_requires_token():
    """WebSocket dashboard endpoint should reject missing tokens with a close code."""

    with TestClient(app) as client:
        try:
            with client.websocket_connect("/ws/dashboard") as websocket:
                assert websocket.close_code == 4401
        except WebSocketDisconnect as exc:
            assert exc.code == 4401


def test_dashboard_websocket_rejects_invalid_token(monkeypatch):
    """Invalid tokens should be rejected consistently with REST auth."""

    def fake_verify(_token):
        raise HTTPException(status_code=401, detail="Invalid token")

    monkeypatch.setattr(auth_manager, "verify_token", fake_verify)

    with TestClient(app) as client:
        try:
            with client.websocket_connect("/ws/dashboard?token=bad") as websocket:
                assert websocket.close_code == 4401
        except WebSocketDisconnect as exc:
            assert exc.code == 4401


def test_dashboard_stats_empty_data_returns_zero():
    """Dashboard stats endpoint should return empty/zero values when no data exists."""

    fake_session = FakeSession([
        FakeResult(scalar_value=0),  # total_scans
        FakeResult(scalar_value=0),  # completed_scans
        FakeResult(scalar_value=0),  # total_hits
        FakeResult(scalar_value=0),  # verified_hits
        FakeResult(fetchall_data=[]),  # service_stats
    ])

    async def override_session():
        return fake_session

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db_session] = override_session

    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/stats/dashboard")

        assert response.status_code == 200
        body = response.json()
        assert body["active_scans"] == 0
        assert body["total_scans"] == 0
        assert body["completed_scans"] == 0
        assert body["total_hits"] == 0
        assert body["verified_hits"] == 0
        assert body["service_breakdown"] == {}
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db_session, None)
