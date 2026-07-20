"""
PhantomSignal — Vulnerability scanning via nuclei (v1.26).

Closes the ASM loop: PhantomSignal maps the surface *and* flags what's
exploitable. Wraps ProjectDiscovery's nuclei behind the external-tool adapter so
it inherits the shared proxy egress and is tagged honestly (proxied vs.
attributable). Emits the ``vulnerability`` result type — already weighted in the
engine's shadow score but never produced until now.

nuclei is optional: absent the binary (or its templates), the module returns
nothing rather than failing the scan. Findings are parsed from nuclei's stable
``-jsonl`` output; parsing is pure and unit-tested against a realistic record.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

from phantomsignal.scrapers._external import ExternalTool

logger = logging.getLogger("phantomsignal.scrapers.vuln_scanner")

# nuclei severities → our normalised ladder (matches scans.py _SEV_ORDER).
_SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info", "": "info",
}
# Relevance so worst-first ordering + the Findings histogram behave.
_SEV_RELEVANCE = {
    "critical": 1.0, "high": 0.85, "medium": 0.6, "low": 0.35, "info": 0.15,
}


def _as_url(target: str) -> str:
    """nuclei wants a URL; bare hosts default to https."""
    t = (target or "").strip()
    if t.startswith(("http://", "https://")):
        return t
    return f"https://{t}"


def parse_nuclei_finding(obj: Dict, opsec: str = "attributable") -> Optional[Dict]:
    """One nuclei JSONL object → a PhantomSignal ``vulnerability`` result dict.

    Tolerates missing fields and both new (``template-id``) and legacy
    (``templateID``) key spellings.
    """
    if not isinstance(obj, dict):
        return None
    tid = obj.get("template-id") or obj.get("templateID")
    if not tid:
        return None
    info = obj.get("info") or {}
    sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), "info")
    desc = (info.get("description") or "").strip()
    return {
        "type": "vulnerability",
        "source": "nuclei",
        "data": {
            "template_id": tid,
            "name": info.get("name") or tid,
            "severity": sev,
            "host": obj.get("host"),
            "matched_at": obj.get("matched-at") or obj.get("matched"),
            "matcher": obj.get("matcher-name"),
            "protocol": obj.get("type"),
            "tags": info.get("tags") or [],
            "reference": info.get("reference") or [],
            "description": desc[:500],
            "extracted": obj.get("extracted-results") or [],
            "opsec": opsec,
        },
        "confidence": 0.9,
        "relevance_score": _SEV_RELEVANCE[sev],
        "is_anomaly": sev in ("critical", "high"),
        "tags": ["vulnerability", sev, "nuclei"],
    }


def summarize(findings: List[Dict], opsec: str) -> Dict:
    """A roll-up finding: counts per severity."""
    counts: Dict[str, int] = {}
    for f in findings:
        s = f["data"]["severity"]
        counts[s] = counts.get(s, 0) + 1
    return {
        "type": "vuln_scan_summary",
        "source": "nuclei",
        "data": {"total": len(findings), "by_severity": counts, "opsec": opsec},
        "confidence": 1.0,
        "relevance_score": 0.2,
        "tags": ["vulnerability", "summary"],
    }


class NucleiScanner(ExternalTool):
    """nuclei adapter. Severity-filtered by default to keep signal high and the
    scan bounded; tunable via ``vuln`` config or scan options."""

    BINARY = "nuclei"
    PROXY_FLAG = "-proxy"
    TIMEOUT = 900.0

    def command(self, target: str, opts: Dict) -> List[str]:
        url = _as_url(target)
        default_sev = self.config.get("vuln", "severity", default="medium,high,critical")
        sev = opts.get("nuclei_severity") or default_sev
        cmd = [
            "nuclei", "-u", url, "-jsonl", "-silent", "-duc",
            "-no-interactsh", "-severity", sev,
        ]
        tags = opts.get("nuclei_tags") or self.config.get("vuln", "tags", default=None)
        if tags:
            cmd += ["-tags", tags]
        rate = self.config.get("vuln", "rate_limit", default=None)
        if rate:
            cmd += ["-rate-limit", str(rate)]
        conc = self.config.get("vuln", "concurrency", default=None)
        if conc:
            cmd += ["-c", str(conc)]
        return cmd

    def parse(self, stdout: str, opsec: str) -> List[Dict]:
        findings: List[Dict] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            r = parse_nuclei_finding(obj, opsec)
            if r:
                findings.append(r)
        if findings:
            findings.append(summarize(findings, opsec))
        return findings
