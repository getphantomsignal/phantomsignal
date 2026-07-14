"""
PhantomSignal Origin Pivot — see past the WAF/CDN to the real origin.

Most scanners waste their effort on the CDN edge (Cloudflare/Akamai/Fastly IPs):
they scan the proxy, get rate-limited by it, and never touch the box that
actually runs the application. This module does what a red teamer does by hand:

  1. Detect whether the target is fronted by a CDN/WAF (response headers + known
     edge IP ranges).
  2. Gather candidate origin IPs from sources the CDN does not hide — historical
     DNS (the origin was usually exposed before it moved behind the CDN),
     subdomains that were never proxied (mail., direct., cpanel., dev., …), and
     Shodan favicon pivots.
  3. Confirm each candidate the only way that is definitive: connect to the IP
     directly with a spoofed ``Host`` header and compare the response to the
     baseline fetched through the edge. A match means you have found the origin
     and can bypass the WAF entirely.

Design: the CDN detection, edge-range classification, and response-similarity
scoring are pure functions (unit-tested); the network I/O degrades gracefully
when optional keys (SecurityTrails, Shodan) are absent.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from phantomsignal.core.http import stealth_client

logger = logging.getLogger("phantomsignal.origin_pivot")

# ── Known edge (CDN/WAF) IPv4 ranges ─────────────────────────────────────────
# A candidate IP inside one of these is still the edge, not the origin. Header
# detection covers CDNs whose ranges are too large/dynamic to embed (Akamai,
# Incapsula); these two publish stable lists and are the common WAF cases.
_CDN_RANGES = [
    ipaddress.ip_network(c) for c in (
        # Cloudflare
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        # Fastly
        "151.101.0.0/16", "199.232.0.0/16",
    )
]

# Response-header signatures → CDN/WAF name. Checked case-insensitively.
_CDN_HEADER_SIGS = (
    ("cloudflare", ("cf-ray", "cf-cache-status")),
    ("cloudflare", ("server", "cloudflare")),
    ("fastly", ("x-served-by", "cache-")),
    ("fastly", ("x-fastly-request-id", "")),
    ("akamai", ("server", "akamai")),
    ("akamai", ("x-akamai-transformed", "")),
    ("cloudfront", ("x-amz-cf-id", "")),
    ("cloudfront", ("server", "cloudfront")),
    ("incapsula", ("x-iinfo", "")),
    ("incapsula", ("x-cdn", "incapsula")),
    ("sucuri", ("server", "sucuri")),
    ("sucuri", ("x-sucuri-id", "")),
)

# Subdomains that are commonly NOT proxied and leak the origin.
_ORIGIN_SUBDOMAINS = (
    "direct", "origin", "origin-www", "cpanel", "whm", "webmail", "mail",
    "smtp", "mx", "ftp", "sftp", "ssh", "dev", "development", "staging",
    "stage", "test", "uat", "beta", "admin", "portal", "vpn", "remote",
    "server", "host", "web", "www2", "old", "legacy", "api", "app", "cdn-origin",
)

_MAX_CANDIDATES = 30


def _hostname(target: str) -> str:
    t = target if "://" in target else f"//{target}"
    return (urlparse(t).hostname or target).lower().strip()


def ip_is_edge(ip: str) -> bool:
    """True if the IP belongs to a known CDN/WAF edge range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CDN_RANGES)


def detect_cdn(headers: Dict[str, str], edge_ips: List[str]) -> Tuple[bool, Optional[str], str]:
    """Return (fronted, cdn_name, detail) from response headers + resolved IPs."""
    low = {k.lower(): (v or "").lower() for k, v in (headers or {}).items()}
    for name, (hdr, needle) in _CDN_HEADER_SIGS:
        if hdr in low and (needle == "" or needle in low[hdr]):
            return True, name, f"header '{hdr}'"
    for ip in edge_ips:
        if ip_is_edge(ip):
            return True, "cloudflare/fastly", f"edge IP {ip}"
    return False, None, "no CDN/WAF signatures in headers or edge IPs"


def fingerprint_response(status: int, text: str) -> Dict:
    """A compact, comparable signature of an HTTP response body."""
    text = text or ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""
    norm = re.sub(r"\s+", " ", text).strip()
    return {
        "status": status,
        "title": title,
        "len": len(text),
        "hash": hashlib.sha1(norm[:8000].encode("utf-8", "ignore")).hexdigest()[:16],
    }


def similarity(base: Dict, cand: Dict) -> float:
    """0..1 similarity between a baseline (through-edge) and candidate response."""
    score = 0.0
    if base.get("title") and base["title"] == cand.get("title"):
        score += 0.6
    if base.get("hash") and base["hash"] == cand.get("hash"):
        score += 0.4
    elif base.get("len") and cand.get("len"):
        ratio = abs(base["len"] - cand["len"]) / max(base["len"], 1)
        if ratio < 0.05:
            score += 0.25
        elif ratio < 0.20:
            score += 0.1
    if base.get("status") == cand.get("status"):
        score += 0.1
    return min(score, 1.0)


class OriginPivot:
    """WAF/CDN → origin discovery module."""

    def __init__(self, config):
        self.config = config
        self.timeout = 8
        self.validate_timeout = 5   # tighter — many candidates probed in parallel

    async def run(self, target: str) -> List[Dict]:
        host = _hostname(target)
        if not host:
            return []
        results: List[Dict] = []

        baseline, edge_ips = await asyncio.gather(
            self._baseline(host), self._resolve_a(host)
        )
        if baseline is None:
            logger.debug("origin_pivot: baseline fetch failed for %s", host)
            return results

        fronted, cdn_name, detail = detect_cdn(baseline["headers"], edge_ips)
        results.append({
            "result_type": "cdn_detected",
            "source": "origin_pivot",
            "confidence": 0.9,
            "relevance_score": 0.55,
            "tags": ["origin-pivot", "cdn"] + ([cdn_name] if cdn_name else []),
            "data": {
                "fronted": fronted,
                "cdn": cdn_name,
                "detail": detail,
                "edge_ips": edge_ips,
                "target": host,
            },
        })
        if not fronted:
            # Not behind a CDN — the resolved IP already is the origin.
            return results

        # Gather candidate origin IPs from every source we can, in parallel.
        gathered = await asyncio.gather(
            self._candidates_dns_history(host),
            self._candidates_subdomains(host),
            self._candidates_favicon(host),
            return_exceptions=True,
        )
        candidates: Dict[str, Set[str]] = {}
        for res in gathered:
            if isinstance(res, Exception):
                logger.debug("origin_pivot candidate source failed: %s", res)
                continue
            for ip, src in res:
                if ip in edge_ips or ip_is_edge(ip):
                    continue   # still the edge, not an origin
                candidates.setdefault(ip, set()).add(src)

        if not candidates:
            return results

        # Confirm each candidate by direct, Host-spoofed connection.
        capped = list(candidates.items())[:_MAX_CANDIDATES]
        verdicts = await asyncio.gather(
            *(self._validate(ip, host, baseline, srcs) for ip, srcs in capped),
            return_exceptions=True,
        )
        for v in verdicts:
            if isinstance(v, dict):
                results.append(v)
        return results

    # ── Baseline + resolution ────────────────────────────────────────────────
    async def _baseline(self, host: str) -> Optional[Dict]:
        """Fetch the site through the edge and fingerprint it."""
        for scheme in ("https", "http"):
            try:
                async with stealth_client(self.config, timeout=self.timeout,
                                          follow_redirects=True) as client:
                    r = await client.get(f"{scheme}://{host}/")
                    fp = fingerprint_response(r.status_code, r.text)
                    fp["headers"] = dict(r.headers)
                    fp["scheme"] = scheme
                    return fp
            except Exception as e:
                logger.debug("baseline %s://%s failed: %s", scheme, host, e)
        return None

    async def _resolve_a(self, host: str) -> List[str]:
        return await self._resolve(host, "A")

    @staticmethod
    async def _resolve(name: str, rtype: str) -> List[str]:
        import dns.resolver

        def _q():
            try:
                res = dns.resolver.Resolver()
                res.lifetime = res.timeout = 4.0
                return [r.to_text() for r in res.resolve(name, rtype)]
            except Exception:
                return []
        return await asyncio.get_event_loop().run_in_executor(None, _q)

    # ── Candidate sources ────────────────────────────────────────────────────
    async def _candidates_dns_history(self, host: str) -> List[Tuple[str, str]]:
        """Historical A records via SecurityTrails — the origin was usually
        exposed before it moved behind the CDN."""
        key = self.config.get_api_key("securitytrails")
        if not key:
            return []
        from phantomsignal.intel.apis.all_apis import SecurityTrailsAPI
        api = SecurityTrailsAPI(self.config)
        # eTLD+1-ish: SecurityTrails history is per-domain.
        data = await api._get(
            f"{api.BASE_URL}/history/{host}/dns/a",
            headers={"APIKEY": key},
        )
        out: List[Tuple[str, str]] = []
        for rec in (data.get("records") or []):
            for v in (rec.get("values") or []):
                ip = v.get("ip")
                if ip:
                    out.append((ip, "dns-history"))
        return out

    async def _candidates_subdomains(self, host: str) -> List[Tuple[str, str]]:
        """Resolve commonly-unproxied subdomains; any that answer are candidates."""
        base = host[4:] if host.startswith("www.") else host
        names = [f"{sub}.{base}" for sub in _ORIGIN_SUBDOMAINS]
        resolved = await asyncio.gather(*(self._resolve(n, "A") for n in names))
        out: List[Tuple[str, str]] = []
        for name, ips in zip(names, resolved):
            for ip in ips:
                out.append((ip, f"subdomain:{name.split('.')[0]}"))
        # MX hosts too — mail servers usually sit on the origin network.
        for mx in await self._resolve(base, "MX"):
            mx_host = mx.split()[-1].rstrip(".") if mx else ""
            if mx_host:
                for ip in await self._resolve(mx_host, "A"):
                    out.append((ip, "mx"))
        return out

    async def _candidates_favicon(self, host: str) -> List[Tuple[str, str]]:
        """Shodan favicon-hash pivot — hosts serving the same favicon that are
        not the CDN edge are strong origin candidates."""
        key = self.config.get_api_key("shodan")
        if not key:
            return []
        try:
            from phantomsignal.scrapers.infra_pivot import (
                find_favicon_url, shodan_favicon_hash,
            )
            async with stealth_client(self.config, timeout=self.timeout,
                                      follow_redirects=True) as client:
                page = await client.get(f"https://{host}/")
                fav = await client.get(find_favicon_url(page.text, f"https://{host}/"))
                if fav.status_code != 200 or not fav.content:
                    return []
                fhash = shodan_favicon_hash(fav.content)
        except Exception as e:
            logger.debug("favicon pivot failed for %s: %s", host, e)
            return []

        try:
            async with stealth_client(self.config, timeout=15) as client:
                r = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": key, "query": f"http.favicon.hash:{fhash}",
                            "minify": "true"},
                )
                data = r.json() if r.status_code == 200 else {}
        except Exception as e:
            logger.debug("shodan favicon search failed: %s", e)
            return []
        return [(m["ip_str"], "favicon-shodan")
                for m in (data.get("matches") or []) if m.get("ip_str")]

    # ── Validation ───────────────────────────────────────────────────────────
    async def _validate(self, ip: str, host: str, baseline: Dict, sources: Set[str]) -> Dict:
        """Connect to the candidate IP directly with a spoofed Host header and
        compare the response to the baseline. This is the confirmation step."""
        best: Optional[Dict] = None
        # "off" profile keeps validation fast-fail (no evasion retries) even when
        # a stealth profile is active for the rest of the scan — we're probing
        # many candidate IPs and want unreachable ones to drop out quickly.
        for scheme in ("https", "http"):
            try:
                async with stealth_client(self.config, profile="off",
                                          timeout=self.validate_timeout,
                                          follow_redirects=False) as client:
                    r = await client.get(f"{scheme}://{ip}/", headers={"Host": host})
                    fp = fingerprint_response(r.status_code, r.text)
                    fp["scheme"] = scheme
                    if best is None or fp["status"] < best["status"]:
                        best = fp
                    # A strong match on the first scheme confirms it — no need to
                    # also probe the other scheme.
                    if similarity(baseline, fp) >= 0.6:
                        break
            except Exception as e:
                logger.debug("validate %s://%s failed: %s", scheme, ip, e)

        srcs = sorted(sources)
        if best is None:
            return {
                "result_type": "origin_candidate",
                "source": "origin_pivot",
                "confidence": 0.3,
                "relevance_score": 0.5,
                "tags": ["origin-pivot", "unreachable"],
                "data": {"ip": ip, "sources": srcs, "reachable": False,
                         "verdict": "unreachable", "host": host},
            }

        score = similarity(baseline, best)
        if score >= 0.6:
            return {
                "result_type": "origin_confirmed",
                "source": "origin_pivot",
                "confidence": round(min(0.99, 0.6 + score / 2), 2),
                "relevance_score": 0.98,
                "is_anomaly": True,
                "tags": ["origin-pivot", "origin", "waf-bypass"],
                "data": {
                    "ip": ip, "sources": srcs, "host": host,
                    "severity": "high",
                    "similarity": round(score, 2),
                    "match": {"title": best["title"], "status": best["status"],
                              "scheme": best["scheme"]},
                    "verdict": "confirmed origin — direct connection bypasses the WAF",
                },
            }
        return {
            "result_type": "origin_candidate",
            "source": "origin_pivot",
            "confidence": round(0.3 + score / 2, 2),
            "relevance_score": 0.6,
            "tags": ["origin-pivot", "candidate"],
            "data": {
                "ip": ip, "sources": srcs, "host": host, "reachable": True,
                "similarity": round(score, 2),
                "response": {"title": best["title"], "status": best["status"],
                             "scheme": best["scheme"]},
                "verdict": "reachable but content differs — possible origin or shared host",
            },
        }
