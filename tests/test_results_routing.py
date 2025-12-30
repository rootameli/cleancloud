"""Regression tests for results endpoint routing order."""

import sys
import types

from fastapi.testclient import TestClient

# Provide a minimal jwt stub so importing the app does not require the external dependency
if "jwt" not in sys.modules:
    sys.modules["jwt"] = types.SimpleNamespace(
        encode=lambda payload, key, algorithm=None: "test-token",
        decode=lambda token, key, algorithms=None: {"sub": "stub"},
        ExpiredSignatureError=Exception,
        JWTError=Exception,
    )

from app.main import app
from app.core.auth import get_current_user
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
        if not self._results:
            return FakeResult()
        return self._results.pop(0)


def override_current_user():
    return {"sub": "test-user"}


def test_counters_route_not_treated_as_hit():
    """Ensure /results/counters is not captured by the hit detail route."""

    fake_session = FakeSession([
        FakeResult(scalar_value=5),  # total
        FakeResult(scalar_value=2),  # validated
    ])

    async def override_session():
        return fake_session

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db_session] = override_session

    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/results/counters")

        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 5
        assert body["valides"] == 2
        assert body["invalides"] == 3
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db_session, None)


def test_providers_route_not_treated_as_hit():
    """Ensure /results/providers is not captured by the hit detail route."""

    fake_session = FakeSession([
        FakeResult(fetchall_data=[("aws", 1), ("sendgrid", 0)]),
    ])

    async def override_session():
        return fake_session

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db_session] = override_session

    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/results/providers")

        assert response.status_code == 200
        body = response.json()
        assert body["aws"] == 1
        assert body["sendgrid"] == 0
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db_session, None)


def test_invalid_hit_id_still_returns_400():
    """Ensure the hit details route still validates ID format after reordering."""

    async def override_session():
        return FakeSession()

    app.dependency_overrides[get_current_user] = override_current_user
    app.dependency_overrides[get_db_session] = override_session

    try:
        with TestClient(app) as client:
            response = client.get("/api/v1/results/not-a-uuid")

        assert response.status_code == 400
        assert response.json().get("detail") == "Invalid hit ID format"
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_db_session, None)
