"""Tests for best-of-breed external tool adapters under stealth governance (v1.26).

Covers the ExternalTool base (availability gating, proxy injection, the real
subprocess→parse pipeline, native fallback), the nuclei vuln parser, and the
subfinder adapter — all without requiring the actual recon binaries or network.
"""
import asyncio

from phantomsignal.scrapers._external import ExternalTool, run_with_fallback
from phantomsignal.scrapers.registry import (
    get_registered_modules, default_module_names,
)
from phantomsignal.scrapers.vuln_scanner import (
    NucleiScanner, parse_nuclei_finding, summarize, _as_url,
)
from phantomsignal.scrapers.subfinder_tool import parse_subfinder, _domain
from phantomsignal.intel.opsec import OpsecLevel, effective_opsec


class _Cfg:
    def get(self, *a, **k):
        return k.get("default")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── ExternalTool base ───────────────────────────────────────────────────────

class _EchoTool(ExternalTool):
    """Uses the real `printf` binary so run() exercises actual subprocess I/O."""
    BINARY = "printf"
    PROXY_FLAG = "-proxy"

    def command(self, target, opts):
        return ["printf", target]          # target doubles as the payload

    def parse(self, stdout, opsec):
        return [{"type": "echo", "source": "t",
                 "data": {"raw": stdout, "opsec": opsec}}]


def test_available_gates_on_binary_presence():
    assert _EchoTool(_Cfg()).available() is True

    class _Absent(ExternalTool):
        BINARY = "phantomsignal-no-such-binary-xyz"

        def command(self, t, o):
            return []

        def parse(self, s, o):
            return []

    assert _Absent(_Cfg()).available() is False


def test_run_executes_subprocess_and_parses():
    res = _run(_EchoTool(_Cfg()).run("hello-world", {}))
    assert res and res[0]["data"]["raw"] == "hello-world"
    # no proxy configured → honestly attributable
    assert res[0]["data"]["opsec"] == "attributable"


def test_proxy_flag_injected_and_opsec_upgrades():
    class _ProxCfg:
        def get(self, section, key, default=None):
            if (section, key) == ("scraper", "proxy"):
                return "http://127.0.0.1:8080"
            return default

    tool = _EchoTool(_ProxCfg())
    cmd = tool._full_command("x", {}, "http://127.0.0.1:8080")
    assert cmd[-2:] == ["-proxy", "http://127.0.0.1:8080"]
    assert tool._opsec_level("http://127.0.0.1:8080") is OpsecLevel.PROXIED
    assert tool._opsec_level(None) is OpsecLevel.ATTRIBUTABLE


def test_run_absent_binary_returns_empty():
    class _Absent(ExternalTool):
        BINARY = "phantomsignal-no-such-binary-xyz"

        def command(self, t, o):
            return []

        def parse(self, s, o):
            return [{"type": "should-not-appear"}]

    assert _run(_Absent(_Cfg()).run("t", {})) == []


# ── native fallback ─────────────────────────────────────────────────────────

def test_fallback_runs_native_when_tool_absent():
    class _Absent(ExternalTool):
        BINARY = "phantomsignal-no-such-binary-xyz"

        def command(self, t, o):
            return []

        def parse(self, s, o):
            return []

    called = {"native": False}

    async def native():
        called["native"] = True
        return [{"type": "native"}]

    res = _run(run_with_fallback(_Absent(_Cfg()), "t", {}, native))
    assert called["native"] and res[0]["type"] == "native"


def test_fallback_runs_native_when_tool_present_but_empty():
    class _EmptyTrue(ExternalTool):
        BINARY = "true"          # real binary, no output

        def command(self, t, o):
            return ["true"]

        def parse(self, s, o):
            return []

    async def native():
        return [{"type": "native"}]

    res = _run(run_with_fallback(_EmptyTrue(_Cfg()), "t", {}, native))
    assert res[0]["type"] == "native"   # flaky/empty tool never drops coverage


# ── nuclei parsing ──────────────────────────────────────────────────────────

def _nuclei_record(**over):
    rec = {
        "template-id": "CVE-2021-44228",
        "info": {"name": "Log4j RCE", "severity": "critical",
                 "tags": ["cve", "rce"], "description": "  jndi lookup rce  ",
                 "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},
        "type": "http", "host": "https://t.test",
        "matched-at": "https://t.test/api", "matcher-name": "body",
    }
    rec.update(over)
    return rec


def test_parse_nuclei_finding_maps_fields_and_severity():
    f = parse_nuclei_finding(_nuclei_record(), "proxied")
    d = f["data"]
    assert f["type"] == "vulnerability"
    assert d["template_id"] == "CVE-2021-44228" and d["severity"] == "critical"
    assert d["matched_at"] == "https://t.test/api"
    assert d["description"] == "jndi lookup rce"     # trimmed
    assert d["opsec"] == "proxied"
    assert f["is_anomaly"] is True                    # critical/high are anomalies
    assert "critical" in f["tags"]


def test_parse_nuclei_tolerates_legacy_key_and_missing_fields():
    f = parse_nuclei_finding({"templateID": "x", "info": {}}, "attributable")
    assert f["data"]["template_id"] == "x" and f["data"]["severity"] == "info"
    assert parse_nuclei_finding({}, "x") is None      # no template id → dropped
    assert parse_nuclei_finding("not-a-dict", "x") is None


def test_nuclei_parse_stdout_adds_summary():
    out = "\n".join([
        '{"template-id":"a","info":{"severity":"high"}}',
        "  ",                                    # blank line ignored
        "not json",                              # junk ignored
        '{"template-id":"b","info":{"severity":"high"}}',
        '{"template-id":"c","info":{"severity":"low"}}',
    ])
    res = NucleiScanner(_Cfg()).parse(out, "proxied")
    assert [r["type"] for r in res].count("vulnerability") == 3
    summary = res[-1]
    assert summary["type"] == "vuln_scan_summary"
    assert summary["data"]["by_severity"] == {"high": 2, "low": 1}
    assert summary["data"]["total"] == 3


def test_nuclei_command_and_url_coercion():
    cmd = NucleiScanner(_Cfg()).command("example.com", {})
    assert cmd[:3] == ["nuclei", "-u", "https://example.com"]
    assert "-jsonl" in cmd and "-severity" in cmd
    assert _as_url("http://x.test") == "http://x.test"   # scheme preserved


def test_summarize_counts():
    findings = [parse_nuclei_finding(_nuclei_record(**{"info": {"severity": s}}),
                                     "proxied")
                for s in ("high", "high", "low")]
    s = summarize(findings, "proxied")
    assert s["data"]["by_severity"] == {"high": 2, "low": 1}
    assert s["data"]["opsec"] == "proxied"


# ── subfinder parsing + domain extraction ───────────────────────────────────

def test_subfinder_parse_dedupes_and_matches_native_shape():
    res = parse_subfinder("a.example.com\nB.EXAMPLE.COM\na.example.com\njunk\n",
                          "example.com", "proxied")
    types = {r["type"] for r in res}
    assert types == {"subdomain", "subdomain_summary"}
    summary = [r for r in res if r["type"] == "subdomain_summary"][0]
    assert summary["data"]["discovered_count"] == 2   # deduped, junk dropped
    assert summary["data"]["opsec"] == "proxied"


def test_domain_extraction():
    assert _domain("https://sub.example.com/path") == "sub.example.com"
    assert _domain("example.com:8443") == "example.com"
    assert _domain("EXAMPLE.com") == "example.com"


# ── dynamic effective opsec ─────────────────────────────────────────────────

def test_opt_in_modules_excluded_from_default_sweep():
    reg = get_registered_modules()
    # registered and selectable...
    assert "vuln_scan" in reg and "subdomain_enum_fast" in reg
    # ...but loud/active + alternative modules never run by default
    defaults = default_module_names()
    assert "vuln_scan" not in defaults
    assert "subdomain_enum_fast" not in defaults
    # a normal module still defaults on
    assert "dns_recon" in defaults


def test_effective_opsec_reflects_actual_egress():
    assert effective_opsec([{"data": {"opsec": "proxied"}}], "attributable") == "proxied"
    # mixed → worst (least masked) wins
    assert effective_opsec(
        [{"data": {"opsec": "proxied"}}, {"data": {"opsec": "attributable"}}],
        "proxied",
    ) == "attributable"
    # nothing self-declared → static tag
    assert effective_opsec([{"data": {}}], "proxied") == "proxied"
    assert effective_opsec([], "stealth_guaranteed") == "stealth_guaranteed"
