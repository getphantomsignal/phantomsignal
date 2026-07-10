"""Tests for ASM change detection (Phase 5, asm_diff).

The diff engine is pure — it works on two lists of result dicts — so it's tested
directly without a DB.
"""
from phantomsignal.intel.asm_diff import (
    result_key, state_signature, changed_fields, diff_results, build_diff_findings,
)


def _r(rtype, data, is_anomaly=False):
    return {"result_type": rtype, "data": data, "is_anomaly": is_anomaly}


# ── keying ──────────────────────────────────────────────────────────────────

def test_result_key_uses_identity_fields():
    a = _r("open_port", {"port": 443, "service": "HTTPS", "banner": "nginx"})
    b = _r("open_port", {"port": 443, "service": "HTTPS", "banner": "apache"})
    # same identity (port) despite different banner
    assert result_key(a) == result_key(b) == ("open_port", "443")


def test_result_key_skips_summaries():
    assert result_key(_r("port_scan_summary", {"open_count": 3})) is None
    assert result_key(_r("asm_diff_summary", {})) is None


def test_state_signature_ignores_volatile_fields():
    a = _r("subdomain", {"subdomain": "x.acme.com", "timestamp": "t1"})
    b = _r("subdomain", {"subdomain": "x.acme.com", "timestamp": "t2"})
    assert state_signature(a) == state_signature(b)


# ── diffing ─────────────────────────────────────────────────────────────────

def _baseline():
    return [
        _r("subdomain", {"subdomain": "www.acme.com"}),
        _r("open_port", {"port": 443, "service": "HTTPS", "banner": "nginx/1.20"}),
        _r("open_port", {"port": 22, "service": "SSH"}),
    ]


def test_diff_detects_added_removed_modified():
    new = [
        _r("subdomain", {"subdomain": "www.acme.com"}),                 # unchanged
        _r("subdomain", {"subdomain": "vpn.acme.com"}),                 # ADDED
        _r("open_port", {"port": 443, "service": "HTTPS", "banner": "nginx/1.25"}),  # MODIFIED
        # port 22 REMOVED
    ]
    d = diff_results(_baseline(), new)
    assert [r["data"]["subdomain"] for r in d.added] == ["vpn.acme.com"]
    assert [r["data"]["port"] for r in d.removed] == [22]
    assert len(d.modified) == 1
    old, mod = d.modified[0]
    assert mod["data"]["port"] == 443
    assert changed_fields(old, mod) == ["banner"]


def test_diff_empty_when_identical():
    d = diff_results(_baseline(), list(_baseline()))
    assert d.is_empty


# ── findings ────────────────────────────────────────────────────────────────

def test_build_findings_flags_new_sensitive_as_anomaly():
    new = _baseline() + [
        _r("subdomain", {"subdomain": "new.acme.com"}),
        _r("credential_exposure", {"identity": "jdoe@acme.com", "host": "acme.com"}),
    ]
    d = diff_results(_baseline(), new)
    findings = build_diff_findings("acme.com", d, {"id": "old"}, {"id": "new"})
    changes = [f for f in findings if f["type"] == "asm_change"]
    # both new assets are sensitive → anomalies
    assert all(c["is_anomaly"] for c in changes if c["data"]["change"] == "new")
    summary = next(f for f in findings if f["type"] == "asm_diff_summary")
    assert summary["data"]["new_assets"] == 2
    assert summary["data"]["new_sensitive"] == 2
    assert summary["data"]["baseline_scan"] == "old"
    assert summary["is_anomaly"] is True


def test_build_findings_removed_not_anomaly():
    d = diff_results(_baseline(), [])          # everything removed
    findings = build_diff_findings("acme.com", d)
    removed = [f for f in findings if f["type"] == "asm_change" and f["data"]["change"] == "removed"]
    assert removed and not any(f["is_anomaly"] for f in removed)
