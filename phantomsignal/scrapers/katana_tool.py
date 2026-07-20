"""
PhantomSignal — katana adapter (v1.26), a fast crawl speed path with the native
Scrapy crawler as fallback.

katana (ProjectDiscovery) crawls far faster than the native crawler and, unlike
the raw-socket scanners, supports a proxy — so it runs under the shared egress
and is tagged **proxied** when a proxy is configured, **attributable** otherwise.
Findings match the native crawler's ``web_page`` shape. Absent the binary, the
native ``WebCrawler`` runs instead.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List

from phantomsignal.scrapers._external import (
    ExternalTool, as_url, run_with_fallback,
)

logger = logging.getLogger("phantomsignal.scrapers.katana")


def parse_katana(stdout: str, opsec: str) -> List[Dict]:
    """katana ``-jsonl`` lines → native-compatible ``web_page`` findings."""
    results: List[Dict] = []
    seen = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        req = obj.get("request") or {}
        endpoint = req.get("endpoint") or obj.get("endpoint")
        if not endpoint or endpoint in seen:
            continue
        seen.add(endpoint)
        resp = obj.get("response") or {}
        headers = resp.get("headers") or {}
        results.append({
            "type": "web_page",
            "source": "katana",
            "data": {
                "url": endpoint,
                "method": req.get("method", "GET"),
                "status_code": resp.get("status_code"),
                "content_type": headers.get("content_type") or headers.get("Content-Type"),
                "opsec": opsec,
            },
            "confidence": 0.9,
            "relevance_score": 0.5,
            "tags": ["web", "crawl"],
        })
    if results:
        results.append({
            "type": "web_crawl_summary",
            "source": "katana",
            "data": {"discovered": len(results), "opsec": opsec},
            "confidence": 1.0,
            "relevance_score": 0.3,
            "tags": ["web", "summary", "crawl"],
        })
    return results


class KatanaTool(ExternalTool):
    BINARY = "katana"
    PROXY_FLAG = "-proxy"       # katana can proxy → masked when a proxy is set
    TIMEOUT = 600.0

    def command(self, target: str, opts: Dict) -> List[str]:
        depth = opts.get("depth", 2)
        return ["katana", "-u", as_url(target), "-jsonl", "-silent",
                "-d", str(depth), "-duc"]

    def parse(self, stdout: str, opsec: str) -> List[Dict]:
        return parse_katana(stdout, opsec)


def run_katana_or_native(config, target: str, opts: Dict):
    """Coroutine: katana when present, else the native Scrapy crawler."""
    from phantomsignal.scrapers.crawler import WebCrawler

    tool = KatanaTool(config)

    def _native():
        return WebCrawler(config).crawl(target, depth=opts.get("depth", 2))

    return run_with_fallback(tool, target, opts or {}, _native)
