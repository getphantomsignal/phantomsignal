"""Tests for the navbar egress-posture summary (stealth_status)."""
from phantomsignal.core.http import stealth_status


class _Cfg:
    """Minimal config stub backed by a nested dict."""
    def __init__(self, scraper=None, evasive=None):
        self._d = {"scraper": scraper or {}, "evasive": evasive or {}}

    def get(self, section, key, default=None):
        return self._d.get(section, {}).get(key, default)


def test_status_off_by_default():
    s = stealth_status(_Cfg())
    assert s["level"] == "off" and s["label"] == "DIRECT"
    assert s["proxied"] is False and s["pool_size"] == 0


def test_status_partial_profile_only():
    # A pacing profile but no proxy → some cover, not masked.
    s = stealth_status(_Cfg(scraper={"stealth_profile": "quiet"}))
    assert s["level"] == "partial"
    assert s["profile"] == "quiet" and s["proxied"] is False


def test_status_partial_proxy_only():
    # A proxy but the 'off' profile → masked IP but no pacing/identity mgmt.
    s = stealth_status(_Cfg(scraper={"proxy": "http://127.0.0.1:8080"}))
    assert s["level"] == "partial" and s["proxied"] is True


def test_status_full_stealth():
    s = stealth_status(_Cfg(scraper={
        "stealth_profile": "paranoid",
        "proxy_pool": ["http://p1:8080", "socks5://p2:1080"],
        "proxy_rotation": "every",
    }))
    assert s["level"] == "stealth"
    assert s["label"] == "PARANOID"
    assert s["pool_size"] == 2 and s["rotation"] == "every"
