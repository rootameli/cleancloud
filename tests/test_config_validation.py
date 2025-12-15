from app.core.config import ConfigManager


def test_default_secret_key_flagged(tmp_path):
    cfg = tmp_path / "config.yml"
    manager = ConfigManager(config_path=str(cfg))
    manager.config.secret_key = "httpx-scanner-change-me-in-production"

    issues = manager.validate_config()

    assert any("Secret key" in issue for issue in issues)


def test_custom_secret_key_ok(tmp_path):
    cfg = tmp_path / "config.yml"
    manager = ConfigManager(config_path=str(cfg))
    manager.config.secret_key = "super-secure-key"

    issues = manager.validate_config()

    assert not any("Secret key" in issue for issue in issues)
