import sys
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

if "jwt" not in sys.modules:
    sys.modules["jwt"] = types.SimpleNamespace(
        encode=lambda payload, key, algorithm=None: "test-token",
        decode=lambda token, key, algorithms=None: {"sub": "stub"},
        ExpiredSignatureError=Exception,
        JWTError=Exception,
    )

from app.main import app
from app.core.auth import get_current_user
from app.core.scanner_enhanced import enhanced_scanner


class DummyScanResult:
    def __init__(self, crack_id="crack-123", payload=None):
        self.crack_id = crack_id
        self._payload = payload or {"id": "scan-id", "status": "queued"}

    def model_dump(self):
        return self._payload


@pytest.fixture(autouse=True)
def override_auth():
    app.dependency_overrides[get_current_user] = lambda: {"sub": "tester"}
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def test_create_scan_with_list_id(monkeypatch, client, tmp_path):
    data_dir = Path("data/lists")
    data_dir.mkdir(parents=True, exist_ok=True)
    list_file = data_dir / "targets.txt"
    list_file.write_text("example.com\napi.example.com\n")
    list_id = str(hash(list_file.name))

    captured = {}

    async def fake_start_scan(scan_request):
        captured["targets"] = scan_request.targets
        return "scan-id"

    monkeypatch.setattr(enhanced_scanner, "start_scan", fake_start_scan)
    monkeypatch.setattr(enhanced_scanner, "get_scan_result", lambda _id: DummyScanResult())

    response = client.post("/api/v1/scans", json={"list_id": list_id})

    assert response.status_code == 200
    assert response.json()["scan_id"] == "scan-id"
    assert captured["targets"] == ["example.com", "api.example.com"]


def test_create_scan_with_targets(monkeypatch, client):
    captured = {}

    async def fake_start_scan(scan_request):
        captured["targets"] = scan_request.targets
        return "scan-id"

    monkeypatch.setattr(enhanced_scanner, "start_scan", fake_start_scan)
    monkeypatch.setattr(enhanced_scanner, "get_scan_result", lambda _id: DummyScanResult())

    response = client.post(
        "/api/v1/scans",
        json={"targets": ["https://example.org"], "concurrency": 10},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    assert captured["targets"] == ["https://example.org"]


def test_create_scan_without_targets_returns_422(client):
    response = client.post("/api/v1/scans", json={})

    assert response.status_code == 422
    assert "No targets provided" in response.json()["detail"]


def test_get_scan_returns_live_result(monkeypatch, client):
    payload = {"id": "scan-id", "status": "running"}
    monkeypatch.setattr(
        enhanced_scanner, "get_scan_result", lambda _id: DummyScanResult(payload=payload)
    )

    response = client.get("/api/v1/scans/scan-id")
    assert response.status_code == 200
    assert response.json()["status"] == "running"
