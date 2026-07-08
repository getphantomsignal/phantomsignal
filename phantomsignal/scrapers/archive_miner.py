"""
PhantomSignal Archive URL Mining — Historical Surface Recovery

Phase 2. Pulls a domain's historical URLs from passive archive sources (no API
keys) and mines them for forgotten attack surface: sensitive files that were
once exposed, admin/internal paths, parameterised endpoints, and subdomains seen
only in old captures. Cheap, passive, high-yield (gau / waybackurls lineage).
Discovered subdomains feed the pivot engine and takeover detector; sensitive
files corroborate the GHDB dork templates.

Design: HTTP I/O in the class; URL parsing / classification / extraction are
pure module-level functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse

import httpx

logger = logging.getLogger("phantomsignal.scrapers.archive_miner")

MAX_URLS = 5000  # cap parsed URLs per source before dedup

# Extensions that are almost always interesting when publicly reachable.
SENSITIVE_EXT = (
    ".bak", ".old", ".backup", ".swp", ".save", ".orig", ".tmp",
    ".sql", ".db", ".sqlite", ".dump",
    ".env", ".config", ".conf", ".ini", ".yml", ".yaml", ".properties",
    ".log", ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z",
    ".pem", ".key", ".p12", ".pfx", ".crt",
    ".json", ".xml", ".csv", ".xls", ".xlsx",
)
# Path substrings that flag interesting endpoints.
SENSITIVE_KEYWORDS = (
    "admin", "internal", "debug", "backup", "config", "phpinfo", "wp-config",
    "/.git", "/.svn", "/.env", "actuator", "swagger", "graphql", "console",
    "upload", "download", "export", "dump", "test", "staging", "dev",
)

_HOST_RE = re.compile(r"^(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def parse_wayback_cdx(payload) -> Set[str]:
    """Wayback CDX JSON: first row is a header, rest are [original, ...]."""
    urls: Set[str] = set()
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return urls
    if not isinstance(payload, list) or len(payload) < 2:
        return urls
    header = payload[0]
    idx = header.index("original") if "original" in header else 0
    for row in payload[1:]:
        if isinstance(row, list) and len(row) > idx:
            urls.add(row[idx])
    return urls


def parse_otx_urllist(payload) -> Set[str]:
    urls: Set[str] = set()
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return urls
    for rec in (payload or {}).get("url_list", []) or []:
        u = (rec or {}).get("url")
        if u:
            urls.add(u)
    return urls


def parse_urlscan(payload) -> Set[str]:
    urls: Set[str] = set()
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return urls
    for rec in (payload or {}).get("results", []) or []:
        u = ((rec or {}).get("page") or {}).get("url")
        if u:
            urls.add(u)
    return urls


def host_of(url: str) -> Optional[str]:
    try:
        return (urlparse(url).netloc.split("@")[-1].split(":")[0] or "").lower() or None
    except Exception:
        return None


def in_scope(url: str, domain: str) -> bool:
    host = host_of(url)
    if not host:
        return False
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith(f".{domain}")


def subdomains_from_urls(urls: Iterable[str], domain: str) -> Set[str]:
    """Distinct in-scope hostnames seen across the URL set."""
    domain = domain.lower().rstrip(".")
    out: Set[str] = set()
    for u in urls:
        h = host_of(u)
        if h and (h == domain or h.endswith(f".{domain}")) and _HOST_RE.match(h):
            out.add(h)
    return out


def extract_params(url: str) -> Set[str]:
    try:
        return set(parse_qs(urlparse(url).query).keys())
    except Exception:
        return set()


def classify_url(url: str) -> List[str]:
    """Tag a URL as interesting: sensitive extension, keyword, or parameterised."""
    tags: List[str] = []
    p = urlparse(url)
    path = p.path.lower()
    if path.endswith(SENSITIVE_EXT):
        tags.append("sensitive-file")
    low = url.lower()
    if any(k in low for k in SENSITIVE_KEYWORDS):
        tags.append("sensitive-path")
    if p.query:
        tags.append("parameterised")
    return tags


def is_interesting(url: str) -> bool:
    return bool(classify_url(url))


# ── miner ───────────────────────────────────────────────────────────────────

class ArchiveURLMiner:
    def __init__(self, config):
        self.config = config

    async def run(self, target: str) -> List[Dict]:
        domain = self._extract_domain(target)
        if not domain:
            return []
        logger.info("Archive URL mining for %s", domain)

        all_urls, source_counts = await self._gather(domain)
        scoped = {u for u in all_urls if in_scope(u, domain)}

        interesting = {u for u in scoped if is_interesting(u)}
        subs = subdomains_from_urls(scoped, domain)
        params: Set[str] = set()
        for u in interesting:
            params |= extract_params(u)

        return self._build_results(domain, scoped, interesting, subs, params, source_counts)

    async def _gather(self, domain: str) -> Tuple[Set[str], Dict[str, int]]:
        async with httpx.AsyncClient(
            timeout=25, follow_redirects=True,
            headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
        ) as client:
            sources = {
                "wayback": self._src_wayback(client, domain),
                "otx": self._src_otx(client, domain),
                "urlscan": self._src_urlscan(client, domain),
            }
            gathered = await asyncio.gather(*sources.values(), return_exceptions=True)

        merged: Set[str] = set()
        counts: Dict[str, int] = {}
        for name, res in zip(sources.keys(), gathered):
            if isinstance(res, Exception):
                logger.debug("archive source %s failed: %s", name, res)
                counts[name] = 0
                continue
            counts[name] = len(res)
            merged |= res
        return merged, counts

    async def _src_wayback(self, client, domain) -> Set[str]:
        url = ("http://web.archive.org/cdx/search/cdx"
               f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit={MAX_URLS}")
        r = await client.get(url)
        return parse_wayback_cdx(r.json()) if r.status_code == 200 else set()

    async def _src_otx(self, client, domain) -> Set[str]:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500")
        return parse_otx_urllist(r.json()) if r.status_code == 200 else set()

    async def _src_urlscan(self, client, domain) -> Set[str]:
        r = await client.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000")
        return parse_urlscan(r.json()) if r.status_code == 200 else set()

    def _build_results(self, domain: str, scoped: Set[str], interesting: Set[str],
                       subs: Set[str], params: Set[str],
                       source_counts: Dict[str, int]) -> List[Dict]:
        results: List[Dict] = []

        for url in sorted(interesting):
            tags = classify_url(url)
            results.append({
                "type": "archive_url",
                "source": "archive_miner",
                "data": {"url": url, "flags": tags, "params": sorted(extract_params(url))},
                "confidence": 0.8,
                "relevance_score": 0.85 if "sensitive-file" in tags else 0.65,
                "tags": ["archive", "url", *tags],
                "is_anomaly": "sensitive-file" in tags,
            })

        # Historical subdomains — feed the pivot engine + takeover detector.
        for sub in sorted(subs):
            if sub == domain:
                continue
            results.append({
                "type": "subdomain",
                "source": "archive_miner",
                "data": {"subdomain": sub, "domain": domain, "origin": "archive"},
                "confidence": 0.6,
                "relevance_score": 0.6,
                "tags": ["archive", "subdomain", "historical"],
            })

        results.append({
            "type": "archive_summary",
            "source": "archive_miner",
            "data": {
                "domain": domain,
                "total_urls": len(scoped),
                "interesting_urls": len(interesting),
                "historical_subdomains": len(subs),
                "unique_params": sorted(params)[:100],
                "param_count": len(params),
                "sources": source_counts,
            },
            "confidence": 1.0,
            "relevance_score": 0.75,
            "tags": ["archive", "summary"],
        })
        return results

    def _extract_domain(self, target: str) -> Optional[str]:
        t = (target or "").strip().lower()
        t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
        return t if t and _HOST_RE.match(t) else None
