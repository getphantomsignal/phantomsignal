"""Tests for JS secret & endpoint mining (Phase 2)."""
from phantomsignal.scrapers.js_miner import (
    extract_script_srcs,
    extract_inline_scripts,
    extract_endpoints,
    find_secrets,
    shannon_entropy,
    _mask,
)


def test_extract_script_srcs_absolutizes_and_filters():
    html = """
      <script src="/static/app.js"></script>
      <script src="https://cdn.example.com/lib.js"></script>
      <script src="/img/logo.svg"></script>
      <script>var x = 1;</script>
    """
    srcs = extract_script_srcs(html, "https://acme.com/")
    assert "https://acme.com/static/app.js" in srcs
    assert "https://cdn.example.com/lib.js" in srcs
    assert not any(s.endswith(".svg") for s in srcs)   # noise ext filtered


def test_extract_inline_scripts():
    html = "<script>var a=1;</script><script src='x.js'></script><script>  </script>"
    inline = extract_inline_scripts(html)
    assert inline == ["var a=1;"]                       # src'd + empty excluded


def test_extract_endpoints():
    js = """
      fetch("https://api.acme.com/v2/users");
      axios.get('/api/internal/secrets');
      const img = "https://cdn.acme.com/logo.png";
      const path = "/graphql";
    """
    eps = extract_endpoints(js)
    assert "https://api.acme.com/v2/users" in eps
    assert "/api/internal/secrets" in eps
    assert "/graphql" in eps
    assert not any(e.endswith(".png") for e in eps)     # image URL filtered


def test_find_secrets_cloud_keys_masked():
    # Build provider-format tokens from fragments so no literal token string
    # exists in source (avoids GitHub push-protection false positives on these
    # deliberately-fake test fixtures). AKIA…EXAMPLE is AWS's public placeholder.
    google = "AIza" + "SyA1234567890abcdefghijklmnopqrstuvw"
    slack = "xoxb" + "-123456789012-" + "abcdefghijklmnop"
    text = (
        'aws = "AKIAIOSFODNN7EXAMPLE"; '
        f'google = "{google}"; '
        f'slack = "{slack}";'
    )
    secrets = find_secrets(text)
    kinds = {s["kind"] for s in secrets}
    assert "AWS Access Key ID" in kinds
    assert "Google API Key" in kinds
    assert "Slack Token" in kinds
    # raw secret never appears in output; masked instead
    for s in secrets:
        assert "AKIAIOSFODNN7EXAMPLE" != s["preview"]
        assert "…" in s["preview"] or "***" in s["preview"]
    aws = next(s for s in secrets if s["kind"] == "AWS Access Key ID")
    assert aws["severity"] == "critical"


def test_find_secrets_entropy_gate():
    # low-entropy assignment should NOT be flagged
    low = 'apikey = "aaaaaaaaaaaaaaaaaaaa"'
    assert not any(s["kind"].startswith("High-entropy") for s in find_secrets(low))
    # high-entropy generic secret SHOULD be flagged
    high = 'secret = "aB3xZ9qL7mK2pR5tV8wY1nC4dF6gH0jS"'
    hits = [s for s in find_secrets(high) if s["kind"].startswith("High-entropy")]
    assert hits and hits[0]["severity"] == "medium"


def test_find_secrets_dedups():
    text = 'a="AKIAIOSFODNN7EXAMPLE"; b="AKIAIOSFODNN7EXAMPLE";'
    aws = [s for s in find_secrets(text) if s["kind"] == "AWS Access Key ID"]
    assert len(aws) == 1


def test_shannon_entropy_and_mask():
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") > 1.5
    assert _mask("AKIAIOSFODNN7EXAMPLE").startswith("AKIA")
    assert _mask("short") == "sh***"
