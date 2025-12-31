import pytest

from app.core import config as config_module
from app.core import httpx_executor as executor_module


def test_config_manager_applies_httpx_env(monkeypatch, tmp_path):
    binary_path = tmp_path / "pd-httpx"
    binary_path.write_text("#!/bin/bash\necho ProjectDiscovery\n")
    binary_path.chmod(0o755)

    monkeypatch.setenv("HTTPX_PATH", str(binary_path))
    manager = config_module.ConfigManager(config_path=tmp_path / "config.yml")

    assert manager.get_config().httpx_path == str(binary_path)


@pytest.mark.anyio
async def test_verify_httpx_binary_accepts_projectdiscovery(monkeypatch, tmp_path):
    binary_path = tmp_path / "pd-httpx"
    binary_path.write_text("#!/bin/bash\necho ProjectDiscovery CLI\n")
    binary_path.chmod(0o755)

    monkeypatch.setenv("HTTPX_PATH", str(binary_path))
    manager = config_module.ConfigManager(config_path=tmp_path / "config.yml")
    monkeypatch.setattr(executor_module, "config_manager", manager)

    executor = executor_module.HTTPxExecutor()
    executor.httpx_path = str(binary_path)

    assert await executor.verify_httpx_binary() is True
