"""Tests for ASM new-asset alerting (Phase 5b, asm_alert).

The payload builder is pure — it works on the diff finding dicts produced by
asm_diff.build_diff_findings — so it's tested directly without a DB or network.
"""
from phantomsignal.intel.asm_diff import diff_results, build_diff_findings
from phantomsignal.intel.asm_alert import (
    diff_summary, new_sensitive_changes, build_alert_payload,
)


def _r(rtype, data, is_anomaly=False):
    return {"result_type": rtype, "data": data, "is_anomaly": is_anomaly}


def _baseline():
    return [
        _r("subdomain", {"subdomain": "www.acme.com"}),
        _r("open_port", {"port": 443, "service": "HTTPS"}),
    ]


def _findings_with_new_sensitive():
    """Diff findings where two new sensitive assets appeared vs baseline."""
    new = _baseline() + [
        _r("subdomain", {"subdomain": "vpn.acme.com"}),
        _r("credential_exposure", {"identity": "jdoe@acme.com", "host": "acme.com"}),
    ]
    diff = diff_results(_baseline(), new)
    return build_diff_findings("acme.com", diff, {"id": "old"}, {"id": "new"})


# ── summary / filtering ───────────────────────────────────────────────────────

def test_diff_summary_extracts_summary_payload():
    findings = _findings_with_new_sensitive()
    s = diff_summary(findings)
    assert s["new_assets"] == 2
    assert s["new_sensitive"] == 2


def test_diff_summary_empty_when_absent():
    assert diff_summary([]) == {}
    assert diff_summary([{"type": "asm_change", "data": {}}]) == {}


def test_new_sensitive_changes_only_new_anomalies():
    findings = _findings_with_new_sensitive()
    sensitive = new_sensitive_changes(findings)
    assert len(sensitive) == 2
    assert all(c["data"]["change"] == "new" and c["is_anomaly"] for c in sensitive)


def test_new_sensitive_excludes_removed_and_nonsensitive():
    # A removed asset and a non-sensitive new tech should not be alerts.
    new = [_r("technology", {"name": "nginx"})]        # new but not sensitive
    diff = diff_results(_baseline(), new)               # baseline removed entirely
    findings = build_diff_findings("acme.com", diff)
    assert new_sensitive_changes(findings) == []


# ── payload ───────────────────────────────────────────────────────────────────

def test_build_payload_none_when_no_sensitive():
    diff = diff_results(_baseline(), list(_baseline()))  # identical → no changes
    findings = build_diff_findings("acme.com", diff)
    assert build_alert_payload("acme.com", findings) is None


def test_build_payload_has_slack_and_discord_shapes():
    findings = _findings_with_new_sensitive()
    payload = build_alert_payload("acme.com", findings)
    assert payload is not None
    # Slack uses `text`, Discord uses `content` — both present and identical.
    assert payload["text"] == payload["content"]
    assert "acme.com" in payload["text"]
    assert payload["new_sensitive"] == 2
    assert payload["new_assets"] == 2
    # structured asset list is complete and typed
    types = {a["type"] for a in payload["assets"]}
    assert types == {"subdomain", "credential_exposure"}


def test_build_payload_truncates_long_asset_list():
    many = _baseline() + [
        _r("subdomain", {"subdomain": f"h{i}.acme.com"}) for i in range(40)
    ]
    diff = diff_results(_baseline(), many)
    findings = build_diff_findings("acme.com", diff)
    payload = build_alert_payload("acme.com", findings)
    assert payload["new_sensitive"] == 40
    assert len(payload["assets"]) == 40           # structured list stays complete
    assert "…and 15 more" in payload["text"]      # message caps at 25 bullets
