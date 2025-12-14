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
