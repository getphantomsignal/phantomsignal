"""Tests for stealth port-scan profiles (Phase 3, port_scanner).

Idle/decoy scans need nmap with raw-packet privileges, which can't run in the
sandbox (unprivileged, no nmap OS access), so the testable core is the nmap
command construction and the honest degradation when the scan can't run.
"""
import asyncio

import pytest

from phantomsignal.scrapers.port_scanner import (
    build_nmap_command, _validate_nmap_operand, PortScanner,
)


class _Cfg:
    def get(self, *a, **k):
        return k.get("default")


def _scanner(nmap=None):
    ps = PortScanner(_Cfg())
    ps._nmap = nmap                     # force nmap present/absent independent of host
    return ps


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── command construction ────────────────────────────────────────────────────

def test_standard_command_has_version_and_os():
    cmd = build_nmap_command("nmap", "192.0.2.1", [80, 443])
    assert "-sV" in cmd and "-O" in cmd
    assert cmd[-1] == "192.0.2.1"
    assert "-p" in cmd and "80,443" in cmd


def test_decoy_command_uses_syn_scan_no_version_os():
    cmd = build_nmap_command("nmap", "192.0.2.1", [443], stealth="decoy")
    assert "-sS" in cmd
    assert cmd[cmd.index("-D") + 1] == "RND:10"     # default decoy spec
    assert "-Pn" in cmd
    # version/OS probes would originate from the real IP → must be absent
    assert "-sV" not in cmd and "-O" not in cmd


def test_decoy_command_custom_decoys():
    cmd = build_nmap_command("nmap", "192.0.2.1", [443],
                             stealth="decoy", decoys="10.0.0.1,ME,10.0.0.2")
    assert cmd[cmd.index("-D") + 1] == "10.0.0.1,ME,10.0.0.2"


def test_idle_command_uses_zombie_no_version_os():
    cmd = build_nmap_command("nmap", "192.0.2.1", [22],
                             stealth="idle", zombie="203.0.113.9")
    assert cmd[cmd.index("-sI") + 1] == "203.0.113.9"
    assert "-Pn" in cmd
    assert "-sV" not in cmd and "-O" not in cmd


def test_idle_requires_zombie():
    with pytest.raises(ValueError):
        build_nmap_command("nmap", "192.0.2.1", [22], stealth="idle")


def test_unknown_stealth_profile_raises():
    with pytest.raises(ValueError):
        build_nmap_command("nmap", "192.0.2.1", [80], stealth="bogus")


# ── argv-injection guard ────────────────────────────────────────────────────

def test_validate_rejects_flaglike_operands():
    with pytest.raises(ValueError):
        _validate_nmap_operand("-oN/etc/passwd", "zombie host")
    with pytest.raises(ValueError):
        _validate_nmap_operand("10.0.0.1,-sV", "decoy spec")   # any flag-like part
    with pytest.raises(ValueError):
        _validate_nmap_operand("", "zombie host")
    # legitimate values pass through unchanged
    assert _validate_nmap_operand("RND:10", "decoy spec") == "RND:10"
    assert _validate_nmap_operand("10.0.0.1,ME,10.0.0.2", "decoy spec") == "10.0.0.1,ME,10.0.0.2"


def test_flaglike_zombie_is_rejected_by_builder():
    with pytest.raises(ValueError):
        build_nmap_command("nmap", "192.0.2.1", [22], stealth="idle", zombie="-oG-")


# ── honest degradation (no nmap / missing zombie) ───────────────────────────

def test_stealth_without_nmap_reports_unavailable():
    ps = _scanner(nmap=None)
    out = _run(ps.scan("192.0.2.1", ports=[80], stealth="decoy"))
    assert len(out) == 1
    r = out[0]
    assert r["type"] == "stealth_unavailable"
    assert r["data"]["profile"] == "decoy"
    assert "nmap is not installed" in r["data"]["reason"]


def test_idle_without_zombie_reports_unavailable():
    ps = _scanner(nmap="/usr/bin/nmap")     # nmap "present" but no zombie given
    out = _run(ps.scan("192.0.2.1", ports=[22], stealth="idle"))
    assert len(out) == 1
    assert out[0]["type"] == "stealth_unavailable"
    assert "zombie" in out[0]["data"]["reason"].lower()


def test_stealth_never_falls_back_to_python_scan():
    # With no nmap, a stealth request must NOT produce open_port/summary findings
    # from a plain connect scan — only the unavailable notice.
    ps = _scanner(nmap=None)
    out = _run(ps.scan("192.0.2.1", ports=[80, 443], stealth="idle", zombie="203.0.113.9"))
    assert [r["type"] for r in out] == ["stealth_unavailable"]


# ── downgrade detection (nmap silently ran a connect scan) ──────────────────

def test_parse_nmap_xml_extracts_scan_type():
    ps = _scanner()
    xml = ('<nmaprun><scaninfo type="syn" protocol="tcp"/>'
           '<host><ports></ports></host></nmaprun>')
    assert ps._parse_nmap_xml(xml)["scan_type"] == "syn"


def test_stealth_reports_downgrade_when_nmap_uses_connect_scan():
    # Simulate nmap running but downgrading -sS → connect (no raw privileges).
    ps = _scanner(nmap="/usr/bin/nmap")

    async def fake_try_nmap(host, ports, stealth=None, decoys=None, zombie=None):
        return {"ports": [], "os": None, "scan_type": "connect"}

    ps._try_nmap = fake_try_nmap
    out = _run(ps.scan("192.0.2.1", ports=[80], stealth="decoy"))
    assert len(out) == 1 and out[0]["type"] == "stealth_unavailable"
    assert "connect scan" in out[0]["data"]["reason"]
    assert "NOT applied" in out[0]["data"]["reason"]


def test_stealth_accepts_genuine_syn_scan():
    ps = _scanner(nmap="/usr/bin/nmap")

    async def fake_try_nmap(host, ports, stealth=None, decoys=None, zombie=None):
        return {"ports": [{"port": 22, "state": "open", "service": "SSH"}],
                "os": None, "scan_type": "syn"}

    ps._try_nmap = fake_try_nmap
    out = _run(ps.scan("192.0.2.1", ports=[22], stealth="decoy"))
    types = [r["type"] for r in out]
    assert "open_port" in types and "port_scan_summary" in types
    summary = next(r for r in out if r["type"] == "port_scan_summary")
    assert summary["data"]["scan_engine"] == "nmap-decoy"
