"""
PhantomSignal — Proxy-pool seeding.

Gets a new operator a working rotating egress pool fast: a curated set of
well-known *free* public proxy-list feeds that can be fetched into the pool, a
tolerant parser for the many `ip:port` / `scheme://ip:port` / auth formats those
feeds (and uploaded files) use, and pool-merge helpers.

Free public proxies are unvetted and frequently dead, rate-limited, or hostile
(a proxy operator can read/modify unencrypted traffic). They are a starting
point for blending in on low-sensitivity recon, not a trust anchor — pair them
with the stealth profile + HTTPS, and prefer your own egress for anything
sensitive. Nothing here is fetched automatically; the operator chooses.

Parser + merge are pure and unit-tested; the network fetch is thin.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

import httpx

# ── Curated free proxy-list feeds ─────────────────────────────────────────────
# Each feed returns plaintext, one proxy per line. ``scheme`` is what a bare
# ``ip:port`` line means for that feed (feeds that already prefix a scheme keep
# it — the parser honours an explicit scheme over this default).
PROXY_SOURCES: Dict[str, Dict[str, str]] = {
    "proxyscrape_http": {
        "name": "ProxyScrape — HTTP",
        "scheme": "http",
        "url": ("https://api.proxyscrape.com/v2/?request=getproxies"
                "&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"),
        "description": "Large, frequently-refreshed HTTP pool.",
    },
    "proxyscrape_socks5": {
        "name": "ProxyScrape — SOCKS5",
        "scheme": "socks5",
        "url": ("https://api.proxyscrape.com/v2/?request=getproxies"
                "&protocol=socks5&timeout=10000&country=all"),
        "description": "SOCKS5 pool (works for any TCP, not just HTTP).",
    },
    "speedx_http": {
        "name": "TheSpeedX — HTTP",
        "scheme": "http",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "description": "Community HTTP list (GitHub, updated hourly).",
    },
    "speedx_socks4": {
        "name": "TheSpeedX — SOCKS4",
        "scheme": "socks4",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "description": "Community SOCKS4 list (GitHub).",
    },
    "speedx_socks5": {
        "name": "TheSpeedX — SOCKS5",
        "scheme": "socks5",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "description": "Community SOCKS5 list (GitHub).",
    },
    "monosans_http": {
        "name": "monosans — HTTP",
        "scheme": "http",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
        "description": "Validated HTTP list (GitHub, checked on update).",
    },
    "proxifly_all": {
        "name": "Proxifly — all protocols",
        "scheme": "http",
        "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
        "description": "Mixed HTTP/SOCKS, each line prefixed with its scheme.",
    },
}

# A proxy line: optional scheme, optional user:pass@, host, :port.
_PROXY_RE = re.compile(
    r"^(?:(?P<scheme>https?|socks4a?|socks5h?)://)?"
    r"(?:(?P<auth>[^@\s/]+)@)?"
    r"(?P<host>[A-Za-z0-9._\-]+):(?P<port>\d{1,5})"
    r"(?::(?P<user>[^:\s]+):(?P<pw>[^:\s]+))?$"   # trailing ip:port:user:pass form
)
_ALLOWED_SCHEMES = ("http", "https", "socks4", "socks4a", "socks5", "socks5h")


def normalize_proxy(raw: str, default_scheme: str = "http") -> Optional[str]:
    """Normalize one proxy line to ``scheme://[auth@]host:port`` or None if it
    isn't a valid proxy. Handles bare ``ip:port``, ``scheme://ip:port``,
    ``user:pass@ip:port``, and the ``ip:port:user:pass`` variant some feeds use."""
    if not raw:
        return None
    line = raw.strip()
    if not line or line.startswith(("#", "//", ";")):
        return None
    m = _PROXY_RE.match(line)
    if not m:
        return None
    port = int(m.group("port"))
    if not 1 <= port <= 65535:
        return None
    scheme = (m.group("scheme") or default_scheme).lower()
    if scheme not in _ALLOWED_SCHEMES:
        return None
    # auth may come as user:pass@host (auth group) or trailing host:port:user:pass.
    auth = m.group("auth")
    if not auth and m.group("user"):
        auth = f"{m.group('user')}:{m.group('pw')}"
    host = m.group("host")
    return f"{scheme}://{auth + '@' if auth else ''}{host}:{port}"


def parse_proxy_lines(text: str, default_scheme: str = "http",
                      limit: Optional[int] = None) -> List[str]:
    """Parse a blob of proxy lines into a de-duplicated, normalized list."""
    out: List[str] = []
    seen = set()
    for line in (text or "").splitlines():
        norm = normalize_proxy(line, default_scheme)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(norm)
            if limit and len(out) >= limit:
                break
    return out


def merge_pool(existing: List[str], additions: List[str],
               cap: int = 1000) -> List[str]:
    """Append new proxies to an existing pool, preserving order, dropping dupes,
    and capping total size so a huge feed can't blow up the pool."""
    out: List[str] = []
    seen = set()
    for p in list(existing or []) + list(additions or []):
        p = (p or "").strip()
        if p and p not in seen:
            seen.add(p)
            out.append(p)
            if len(out) >= cap:
                break
    return out


def is_fetchable_url(url: str) -> bool:
    """Only http(s) list URLs may be fetched (no file:// / gopher:// etc.)."""
    return isinstance(url, str) and url.strip().lower().startswith(("http://", "https://"))


async def fetch_proxy_source(url: str, default_scheme: str = "http",
                             timeout: float = 15.0,
                             limit: int = 500) -> List[str]:
    """Fetch a proxy-list feed and parse it. Raises ValueError on a non-http URL;
    network/HTTP errors propagate to the caller to surface."""
    if not is_fetchable_url(url):
        raise ValueError("Proxy source URL must be http:// or https://")
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 headers={"User-Agent": "PhantomSignal-OSINT/1.0"}) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return parse_proxy_lines(resp.text, default_scheme, limit=limit)
