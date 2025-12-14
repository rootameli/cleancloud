from app.core.httpx_executor import HTTPxExecutor


def test_httpx_health_reports_missing_binary_when_unset():
    executor = HTTPxExecutor()
    executor.httpx_path = "/nonexistent/httpx-binary"

    healthy, detail = executor.check_httpx_health()

    assert healthy is False
    assert "missing" in detail or "not executable" in detail


def test_httpx_path_prefers_env_override(monkeypatch):
    monkeypatch.setenv("HTTPX_PATH", "/tmp/fake-httpx")

    executor = HTTPxExecutor()

    assert executor.httpx_path == "/tmp/fake-httpx"


def test_httpx_health_reports_missing_when_env_points_to_nowhere(monkeypatch):
    missing_path = "/tmp/definitely-missing-httpx"
    monkeypatch.setenv("HTTPX_PATH", missing_path)

    executor = HTTPxExecutor()

    assert executor.httpx_path == missing_path

    healthy, detail = executor.check_httpx_health()

    assert healthy is False
    assert "missing" in detail.lower()


def test_get_scan_stats_returns_copy(monkeypatch):
    monkeypatch.delenv("HTTPX_PATH", raising=False)
    executor = HTTPxExecutor()

    executor.scan_stats["scan-123"] = {"processed_urls": 10, "start_time": 1.0}

    stats = executor.get_scan_stats("scan-123")

    assert stats == {"processed_urls": 10, "start_time": 1.0}
    assert stats is not executor.scan_stats["scan-123"]
