"""Tests for scraper/egress settings persistence across restarts.

Uses a temp user-config path and rebuilds the config singleton to prove a real
save → reload round trip, restoring the original singleton afterwards so other
tests are unaffected.
"""
import pytest

import phantomsignal.core.config as cfgmod


@pytest.fixture
def fresh_config(tmp_path, monkeypatch):
    """A config instance backed by a throwaway user-config file."""
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(cfgmod, "_USER_CONFIG_PATH", path)
    orig = cfgmod.PhantomSignalConfig._instance
    cfgmod.PhantomSignalConfig._instance = None
    try:
        yield cfgmod.PhantomSignalConfig(), path
    finally:
        cfgmod.PhantomSignalConfig._instance = orig


def _reload():
    cfgmod.PhantomSignalConfig._instance = None
    return cfgmod.PhantomSignalConfig()


def test_scraper_egress_survives_reload(fresh_config):
    c, path = fresh_config
    c.set("scraper", "proxy_pool", value=["http://192.0.2.4:8080", "socks5://198.51.100.8:1080"])
    c.set("scraper", "stealth_profile", value="paranoid")
    c.set("scraper", "proxy_rotation", value="every")
    c.set("scraper", "tls_impersonate", value=True)
    c.persist()
    assert path.exists()

    c2 = _reload()
    assert c2.get("scraper", "proxy_pool") == ["http://192.0.2.4:8080", "socks5://198.51.100.8:1080"]
    assert c2.get("scraper", "stealth_profile") == "paranoid"
    assert c2.get("scraper", "proxy_rotation") == "every"
    assert c2.get("scraper", "tls_impersonate") is True


def test_persist_keeps_api_keys_and_scraper_together(fresh_config):
    c, path = fresh_config
    # A service with no env-var mapping, so nothing overrides the persisted value.
    c.set_api_key("unit_test_svc", "SECRET123")   # triggers a persist
    c.set("scraper", "proxy", value="http://127.0.0.1:8080")
    c.persist()

    c2 = _reload()
    assert c2.get_api_key("unit_test_svc") == "SECRET123"
    assert c2.get("scraper", "proxy") == "http://127.0.0.1:8080"


def test_persist_does_not_clobber_unmanaged_keys(fresh_config):
    c, path = fresh_config
    # Simulate a manual user edit with a key we don't manage.
    path.write_text("custom:\n  hello: world\n")
    c.set("scraper", "proxy_rotation", value="every")
    c.persist()

    import yaml
    on_disk = yaml.safe_load(path.read_text())
    assert on_disk["custom"] == {"hello": "world"}    # preserved
    assert on_disk["scraper"]["proxy_rotation"] == "every"


def test_scraper_persist_does_not_leak_inmemory_api_keys(fresh_config):
    c, path = fresh_config
    # Simulate an env-loaded key living only in memory.
    c._config["api_keys"]["ephemeral_env_key"] = "FROMENV"
    c.persist()   # scraper path — must not copy in-memory keys to disk
    import yaml
    on_disk = yaml.safe_load(path.read_text()) or {}
    assert "ephemeral_env_key" not in (on_disk.get("api_keys") or {})


def test_persist_only_writes_whitelisted_scraper_keys(fresh_config):
    c, path = fresh_config
    c.persist()
    import yaml
    saved = yaml.safe_load(path.read_text()).get("scraper", {})
    # Volatile/derived keys must not be frozen into the user file.
    assert "timeout" not in saved and "user_agent_rotation" not in saved
    assert set(saved).issubset(set(cfgmod.PhantomSignalConfig._PERSIST_SCRAPER_KEYS))
