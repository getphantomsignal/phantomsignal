"""
PhantomSignal — subfinder adapter (v1.26), a best-of-breed speed path for
subdomain enumeration with the pure-Python enumerator as fallback.

subfinder (ProjectDiscovery) is much faster and hits more passive sources than
the native module. When installed it runs under the shared proxy egress and its
output is normalised to the *same* result shape the native module emits, so the
rest of the pipeline (pivot, takeover, categories) is unchanged. Absent the
binary, the native ``SubdomainEnumerator`` runs instead — external tools stay
strictly optional.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
from typing import Dict, List
from urllib.parse import urlparse

from phantomsignal.scrapers._external import ExternalTool, run_with_fallback

logger = logging.getLogger("phantomsignal.scrapers.subfinder")


def _domain(target: str) -> str:
    """Bare registrable-ish domain for subfinder's ``-d``."""
    t = (target or "").strip()
    if "://" in t:
        t = urlparse(t).netloc or t
    return t.split("/")[0].split(":")[0].lstrip(".").lower()


def parse_subfinder(stdout: str, domain: str, opsec: str) -> List[Dict]:
    """subfinder ``-silent`` hostnames → native-compatible result dicts."""
    subs = sorted({
        line.strip().lower()
        for line in stdout.splitlines()
        if line.strip() and "." in line
    })
    results: List[Dict] = []
    for s in subs:
        results.append({
            "type": "subdomain",
            "source": "subfinder",
            "data": {"subdomain": s, "domain": domain,
                     "discovery": "subfinder", "opsec": opsec},
            "confidence": 1.0,
            "relevance_score": 0.78,
            "tags": ["dns", "subdomain", "passive"],
        })
    if results:
        results.append({
            "type": "subdomain_summary",
            "source": "subfinder",
            "data": {
                "domain": domain,
                "discovered_count": len(subs),
                "sources": {"subfinder": len(subs)},
                "subdomains": list(subs),
                "opsec": opsec,
            },
            "confidence": 1.0,
            "relevance_score": 0.85,
            "tags": ["dns", "subdomain", "summary", "passive"],
        })
    return results


class SubfinderTool(ExternalTool):
    BINARY = "subfinder"
    PROXY_FLAG = "-proxy"
    TIMEOUT = 300.0

    def command(self, target: str, opts: Dict) -> List[str]:
        return ["subfinder", "-d", _domain(target), "-silent", "-duc"]

    def parse(self, stdout: str, opsec: str) -> List[Dict]:
        return parse_subfinder(stdout, _domain(self._target), opsec)

    async def run(self, target: str, opts=None) -> List[Dict]:
        # stash target so parse() (which only gets stdout) can label the domain
        self._target = target
        return await super().run(target, opts)


def run_subfinder_or_native(config, target: str, opts: Dict):
    """Coroutine: subfinder when present, else the native enumerator."""
    from phantomsignal.scrapers.subdomain_enum import SubdomainEnumerator

    tool = SubfinderTool(config)

    def _native():
        return SubdomainEnumerator(config).run(target)

    return run_with_fallback(tool, target, opts or {}, _native)
