"""Tests for the signature engine (Phase 1)."""
from phantomsignal.intel.signatures import SignatureEngine, load_templates, Signature


def test_templates_load_and_validate():
    sigs = load_templates()
    assert sigs, "expected bundled templates to load"
    ids = {s.id for s in sigs}
    assert "ghdb-exposed-config-and-secrets" in ids
    assert "subdomain-takeover-fingerprint" in ids
    # every template resolves to exactly one mode
    assert all(s.kind in ("dork", "match") for s in sigs)


def test_dork_rendering_scopes_to_target():
    engine = SignatureEngine()
    findings = engine.evaluate("acme.com", results=[], target_kind="domain")
    dorks = [f for f in findings if f["type"] == "dork"]
    assert dorks
    queries = [q for f in dorks for q in f["data"]["queries"]]
    assert any("site:acme.com" in q for q in queries)
    assert all("{target}" not in q for q in queries)


def test_dork_target_kind_gate():
    engine = SignatureEngine()
    # dork templates gate on domain/subdomain — an IP target should not match them
    findings = engine.evaluate("8.8.8.8", results=[], target_kind="ip")
    assert not [f for f in findings if f["type"] == "dork"]


def test_match_fires_on_takeover_fingerprint():
    engine = SignatureEngine()
    results = [{
        "type": "web_content",
        "source": "crawler",
        "data": {"url": "http://x.acme.com", "body": "NoSuchBucket - the bucket is gone"},
        "tags": [],
    }]
    findings = engine.evaluate("acme.com", results, target_kind="domain")
    matches = [f for f in findings if f["type"] == "signature_match"]
    assert any(f["data"]["signature_id"] == "subdomain-takeover-fingerprint"
               for f in matches)
    assert any(f["data"]["severity"] == "high" for f in matches)


def test_match_regex_on_data_key_and_aws_key():
    engine = SignatureEngine()
    results = [
        {"type": "web_content", "source": "hunter",
         "data": {"url": "https://acme.com/.git/config"}, "tags": []},
        {"type": "web_content", "source": "hunter",
         "data": {"body": "key=AKIAIOSFODNN7EXAMPLE more"}, "tags": []},
    ]
    findings = engine.evaluate("acme.com", results, target_kind="domain")
    hits = [f for f in findings
            if f["data"].get("signature_id") == "exposed-vcs-and-cloud-keys"]
    assert len(hits) == 2
    assert all(f["data"]["severity"] == "critical" for f in hits)


def test_bad_template_is_skipped(tmp_path):
    (tmp_path / "broken.yaml").write_text("id: x\ninfo: {name: broken}\n")  # no match/dork
    (tmp_path / "ok.yaml").write_text(
        "id: ok\ninfo: {name: ok, severity: low}\n"
        "dork: {target-kinds: [domain], queries: ['site:{target} test']}\n"
    )
    sigs = load_templates(tmp_path)
    assert {s.id for s in sigs} == {"ok"}
