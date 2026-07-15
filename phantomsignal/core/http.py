"""
PhantomSignal — Shared stealth HTTP client.

Every target-facing scraper routes through this module instead of constructing
its own ``httpx.AsyncClient``. Centralising the client is what makes the evasion
config real: proxy egress, User-Agent / header identity, per-host adaptive rate
limiting, timing jitter, and defensive-response backoff all live here, in one
place, applied uniformly.

Design notes (why this beats bolting evasion onto each scraper):

* **Adaptive, per-host pacing (AIMD).** Instead of a fixed global delay, each
  host gets its own congestion-control loop: on 429/503/WAF-challenge we
  multiplicatively slow down and honour ``Retry-After``; on a run of clean
  responses we additively speed back up. This learns a target's real tolerance
  rather than guessing, and it is what keeps a source IP from getting burned.

* **Sticky identity per host.** A single client that flips User-Agent on every
  request is *itself* a fingerprint. We pick one realistic browser identity per
  host and keep it, with a header set that matches the UA family and ordering.

* **Defensive-response awareness.** Most scanners plough ahead when a target
  starts returning challenges — escalating detection. We detect WAF/CDN
  challenge signatures and back off (or surface the block) instead.

The client only fronts *target*-facing traffic. Calls to our own third-party
intel APIs and DoH resolvers deliberately do NOT go through here — evading the
target must not mangle the auth/UA those providers expect.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
import email.utils
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Dict, Iterator, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("phantomsignal.http")


# ── Attribution telemetry ─────────────────────────────────────────────────────
# The OPSEC flagship promises operators an honest answer to "what did this scan
# leak?". To answer it we tally, per scan, every request that actually left the
# box: whether it went out through a proxy or direct, whether the TLS/HTTP2
# fingerprint was impersonated (and as which browser), and how often a defence
# challenged us. A scan opens an ``attribution_scope`` (a contextvar), and every
# StealthClient underneath — however deep in the module tree — records into it.


@dataclass
class AttributionLedger:
    """Per-scan tally of egress that left the operator's box."""
    total: int = 0                                   # requests that egressed
    proxied: int = 0                                 # via a proxy (masked)
    direct: int = 0                                  # direct from our IP
    impersonated: int = 0                            # with a spoofed JA3/JA4
    waf_blocks: int = 0                              # defence-challenge responses
    backoffs: int = 0                                # adaptive backoff sleeps
    hosts: Set[str] = field(default_factory=set)
    proxies_used: Set[str] = field(default_factory=set)
    ja3_profiles: Dict[str, int] = field(default_factory=dict)   # imp target → n
    block_names: Dict[str, int] = field(default_factory=dict)    # waf name → n

    def record_request(self, host: str, proxy: Optional[str],
                       impersonate_target: Optional[str]) -> None:
        self.total += 1
        if host:
            self.hosts.add(host)
        if proxy:
            self.proxied += 1
            self.proxies_used.add(proxy)
        else:
            self.direct += 1
        if impersonate_target:
            self.impersonated += 1
            self.ja3_profiles[impersonate_target] = (
                self.ja3_profiles.get(impersonate_target, 0) + 1
            )

    def record_block(self, name: Optional[str]) -> None:
        self.waf_blocks += 1
        if name:
            self.block_names[name] = self.block_names.get(name, 0) + 1

    def record_backoff(self) -> None:
        self.backoffs += 1

    def summary(self) -> Dict:
        """A JSON-serialisable snapshot for storage/rendering."""
        proxied_pct = round(100.0 * self.proxied / self.total, 1) if self.total else 0.0
        return {
            "total_requests": self.total,
            "proxied": self.proxied,
            "direct": self.direct,
            "proxied_pct": proxied_pct,
            "impersonated": self.impersonated,
            "waf_blocks": self.waf_blocks,
            "backoffs": self.backoffs,
            "hosts_touched": len(self.hosts),
            "proxies_used": len(self.proxies_used),
            "ja3_profiles": dict(self.ja3_profiles),
            "block_names": dict(self.block_names),
        }


_current_ledger: contextvars.ContextVar[Optional[AttributionLedger]] = (
    contextvars.ContextVar("ps_attribution_ledger", default=None)
)


@contextlib.contextmanager
def attribution_scope(ledger: Optional[AttributionLedger] = None) -> Iterator[AttributionLedger]:
    """Activate a ledger for the duration of a scan. Every StealthClient request
    made within (including in child tasks) records into it."""
    led = ledger if ledger is not None else AttributionLedger()
    token = _current_ledger.set(led)
    try:
        yield led
    finally:
        _current_ledger.reset(token)


# curl_cffi (curl-impersonate) is an optional dependency that lets us present a
# real browser's TLS (JA3/JA4) + HTTP/2 fingerprint instead of Python's static,
# trivially-fingerprinted stack. Absent it, we fall back to httpx transparently.
try:
    from curl_cffi.requests import AsyncSession as _CurlSession
    from curl_cffi.requests.exceptions import RequestException as _CurlError
    _CURL_AVAILABLE = True
    _CURL_ERRORS: Tuple[type, ...] = (_CurlError,)
except Exception:  # pragma: no cover - optional dependency
    _CurlSession = None
    _CURL_AVAILABLE = False
    _CURL_ERRORS = ()

_TRANSPORT_ERRORS: Tuple[type, ...] = (httpx.TimeoutException, httpx.TransportError) + _CURL_ERRORS

# ── Browser identities ───────────────────────────────────────────────────────
# Current-ish desktop browsers. Each entry is (User-Agent, matching header set).
# Header order is preserved by httpx, so we keep a realistic ordering per family.
_IDENTITIES: Tuple[Tuple[str, Dict[str, str]], ...] = (
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not.A/Brand";v="24"',
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Upgrade-Insecure-Requests": "1",
        },
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
        },
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        },
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Upgrade-Insecure-Requests": "1",
        },
    ),
)

# curl_cffi impersonation target per identity index — the TLS/HTTP2 fingerprint
# is matched to the same browser family as the identity's User-Agent + headers,
# so a defender sees a consistent Chrome/Safari/Firefox across UA, header order,
# and JA3/JA4. Rotating identity (on a burn) therefore rotates the JA3 too.
_IMPERSONATE = ("chrome124", "safari170", "firefox133", "firefox133")


# ── Stealth profiles ─────────────────────────────────────────────────────────
# Tunables per operating posture. base_interval is the *minimum* seconds between
# request starts to a single host before adaptation; jitter is added on top.


@dataclass(frozen=True)
class Profile:
    name: str
    max_concurrency: int      # cap on simultaneous requests to one host
    base_interval: float      # floor for per-host spacing (seconds)
    interval_cap: float       # ceiling adaptation may raise spacing to
    jitter: Tuple[float, float]
    max_retries: int
    rotate_identity: bool


PROFILES: Dict[str, Profile] = {
    # Fast and loud — legacy behaviour, for authorised noisy scans.
    "off":      Profile("off", 30, 0.0, 0.0, (0.0, 0.0), 1, False),
    # Blend in: bounded concurrency, light spacing + jitter, honour backoff.
    "quiet":    Profile("quiet", 8, 0.25, 8.0, (0.15, 0.7), 2, True),
    # Low and slow: minimal concurrency, heavy jitter, patient backoff.
    "paranoid": Profile("paranoid", 2, 1.5, 45.0, (0.5, 3.0), 3, True),
}

# Response signatures that mean "a defence answered, not the app".
_WAF_BODY_MARKERS = (
    "just a moment",              # Cloudflare interstitial
    "attention required",         # Cloudflare block
    "cf-mitigated",
    "access denied",
    "request unsuccessful",       # Incapsula
    "incident id",                # Incapsula/Imperva
    "captcha",
    "are you a robot",
    "akamai",
)
_WAF_SERVER_MARKERS = ("cloudflare", "akamai", "sucuri", "incapsula", "imperva", "awselb")


def looks_like_waf(resp: httpx.Response) -> Optional[str]:
    """Return a best-guess WAF/CDN name if the response looks like a challenge
    or block rather than the origin app, else None."""
    status = resp.status_code
    server = resp.headers.get("server", "").lower()
    if resp.headers.get("cf-mitigated") or resp.headers.get("cf-ray") and status in (403, 429, 503):
        return "cloudflare"
    if status in (401, 403, 406, 429, 503):
        for m in _WAF_SERVER_MARKERS:
            if m in server:
                return m
        # Only sniff the body on suspicious statuses; keep it cheap.
        try:
            body = resp.text[:2048].lower()
        except Exception:
            body = ""
        for m in _WAF_BODY_MARKERS:
            if m in body:
                return m
    return None


def _retry_after_seconds(resp: httpx.Response, cap: float) -> Optional[float]:
    """Parse a Retry-After header (delta-seconds or HTTP-date). Capped."""
    val = resp.headers.get("retry-after")
    if not val:
        return None
    val = val.strip()
    if val.isdigit():
        return min(float(val), cap)
    parsed = email.utils.parsedate_to_datetime(val)
    if parsed is None:
        return None
    delta = parsed.timestamp() - time.time()
    return min(max(delta, 0.0), cap) if delta > 0 else 0.0


@dataclass
class _HostState:
    """Per-host adaptive pacing state."""
    ident: int                       # index into _IDENTITIES (sticky identity)
    interval: float                  # current min spacing between request starts
    next_allowed: float = 0.0        # monotonic time the next start is permitted
    success_streak: int = 0
    sem: Optional[asyncio.Semaphore] = None
    lock: Optional[asyncio.Lock] = None
    blocked: bool = False            # sticky "we were challenged here" flag


class _RateLimiter:
    """Owns per-host pacing state and the AIMD adaptation loop."""

    def __init__(self, profile: Profile):
        self.profile = profile
        self._hosts: Dict[str, _HostState] = {}

    def _state(self, host: str) -> _HostState:
        st = self._hosts.get(host)
        if st is None:
            st = _HostState(
                ident=random.randrange(len(_IDENTITIES)),
                interval=self.profile.base_interval,
                sem=asyncio.Semaphore(self.profile.max_concurrency),
                lock=asyncio.Lock(),
            )
            self._hosts[host] = st
        return st

    def identity(self, host: str) -> Tuple[str, Dict[str, str]]:
        idx = self._state(host).ident if self.profile.rotate_identity else 0
        ua, headers = _IDENTITIES[idx]
        return ua, dict(headers)

    def reroll_identity(self, host: str) -> None:
        """Assign this host a *different* browser identity (used when an egress
        burns, so the retry looks like a fresh client, not the same one)."""
        if len(_IDENTITIES) < 2:
            return
        st = self._state(host)
        choices = [i for i in range(len(_IDENTITIES)) if i != st.ident]
        st.ident = random.choice(choices)

    def impersonate(self, host: str) -> str:
        """curl_cffi impersonation target matching this host's identity."""
        idx = self._state(host).ident if self.profile.rotate_identity else 0
        return _IMPERSONATE[idx % len(_IMPERSONATE)]

    async def acquire(self, host: str) -> asyncio.Semaphore:
        """Wait for a paced+jittered slot. Returns the held semaphore so the
        caller releases it after the request completes."""
        st = self._state(host)
        await st.sem.acquire()
        async with st.lock:
            now = time.monotonic()
            start = max(now, st.next_allowed)
            st.next_allowed = start + st.interval
            wait = start - now
        lo, hi = self.profile.jitter
        if hi > 0:
            wait += random.uniform(lo, hi)
        if wait > 0:
            await asyncio.sleep(wait)
        return st.sem

    def penalize(self, host: str, cooldown: Optional[float] = None) -> None:
        """A defensive response landed — slow this host down hard (AIMD MD)."""
        st = self._state(host)
        st.success_streak = 0
        st.blocked = True
        base = max(st.interval, self.profile.base_interval, 0.5)
        st.interval = min(self.profile.interval_cap, base * 2.0)
        if cooldown:
            # Push the next permitted start out by the server-requested cooldown.
            st.next_allowed = max(st.next_allowed, time.monotonic() + cooldown)

    def reward(self, host: str) -> None:
        """A clean response — after a short streak, ease pacing back (AIMD AI)."""
        st = self._state(host)
        st.success_streak += 1
        if st.success_streak >= 5 and st.interval > self.profile.base_interval:
            st.interval = max(self.profile.base_interval, st.interval * 0.8)
            st.success_streak = 0


@dataclass
class _ProxyHealth:
    """Rolling health for one egress proxy."""
    fails: int = 0
    disabled_until: float = 0.0     # monotonic time the proxy is usable again
    requests: int = 0


class ProxyPool:
    """A rotating pool of egress proxies with per-proxy health tracking.

    ``None`` is a valid pool entry meaning "direct" (no proxy). Rotation modes:

    * ``sticky``  — a host keeps one egress until it burns (block / repeated
      failure), then rotates to a fresh healthy proxy. Most realistic: a real
      client session stays on one IP.
    * ``every``   — round-robin a fresh egress on every request, to spread load
      as widely as possible.

    A proxy that fails ``fail_threshold`` times is benched for an exponentially
    growing cooldown; a clean response clears its failure count. When nothing is
    healthy the pool degrades to the soonest-to-recover entry rather than hard
    failing — losing a proxy should slow you down, not stop you.
    """

    def __init__(
        self,
        proxies,
        *,
        rotation: str = "sticky",
        fail_threshold: int = 3,
        cooldown: float = 60.0,
    ):
        # Preserve order, drop dupes; empty pool means direct-only.
        seen: list = []
        for p in (proxies or []):
            p = p or None
            if p not in seen:
                seen.append(p)
        self._proxies = seen or [None]
        self._health: Dict[Optional[str], _ProxyHealth] = {p: _ProxyHealth() for p in self._proxies}
        self._rotation = rotation if rotation in ("sticky", "every") else "sticky"
        self._fail_threshold = fail_threshold
        self._cooldown = cooldown
        self._rr = 0
        self._assign: Dict[str, Optional[str]] = {}

    @property
    def size(self) -> int:
        return len(self._proxies)

    def _healthy(self, proxy: Optional[str]) -> bool:
        return time.monotonic() >= self._health[proxy].disabled_until

    def _next_healthy(self, exclude: Optional[str] = "__none__") -> Optional[str]:
        n = len(self._proxies)
        for i in range(n):
            p = self._proxies[(self._rr + i) % n]
            if p == exclude:
                continue
            if self._healthy(p):
                self._rr = (self._rr + i + 1) % n
                return p
        # Nothing healthy — fall back to the soonest-to-recover (excluding the
        # burned one when we can), so the pool degrades instead of failing.
        candidates = [p for p in self._proxies if p != exclude] or self._proxies
        return min(candidates, key=lambda p: self._health[p].disabled_until)

    def for_host(self, host: str) -> Optional[str]:
        """The egress this request should use."""
        if self._rotation == "every":
            return self._next_healthy()
        # ``None`` is a valid (direct) assignment, so test membership, not truth.
        if host in self._assign and self._healthy(self._assign[host]):
            return self._assign[host]
        p = self._next_healthy()
        self._assign[host] = p
        return p

    def rotate_host(self, host: str) -> Optional[str]:
        """Move a host to a different healthy egress (after a burn)."""
        cur = self._assign.get(host)
        nxt = self._next_healthy(exclude=cur)
        self._assign[host] = nxt
        return nxt

    def penalize(self, proxy: Optional[str]) -> None:
        h = self._health.get(proxy)
        if h is None or self.size == 1:
            return   # nothing to rotate to — benching our only egress is pointless
        h.fails += 1
        if h.fails >= self._fail_threshold:
            factor = 2 ** min(h.fails - self._fail_threshold, 4)
            h.disabled_until = time.monotonic() + self._cooldown * factor

    def reward(self, proxy: Optional[str]) -> None:
        h = self._health.get(proxy)
        if h is None:
            return
        h.fails = 0
        h.disabled_until = 0.0
        h.requests += 1

    def status(self) -> list:
        now = time.monotonic()
        return [
            {
                "proxy": p or "direct",
                "healthy": now >= self._health[p].disabled_until,
                "fails": self._health[p].fails,
                "requests": self._health[p].requests,
            }
            for p in self._proxies
        ]


class StealthClient:
    """Drop-in async HTTP client with evasion baked in.

    Usage mirrors ``httpx.AsyncClient``::

        async with stealth_client(config) as client:
            resp = await client.get(url)

    Callers may still pass ``headers=`` for request-specific fields; the stealth
    identity (User-Agent + browser header set) is used as the base and, when
    stealth is active, the caller's User-Agent is intentionally ignored so we
    don't re-introduce a scanner fingerprint.
    """

    def __init__(
        self,
        *,
        profile: Profile,
        timeout: float = 30.0,
        verify: bool = False,
        follow_redirects: bool = True,
        proxy: Optional[str] = None,
        pool: Optional[list] = None,
        rotation: str = "sticky",
        impersonate: bool = False,
    ):
        self._profile = profile
        self._limiter = _RateLimiter(profile)
        self._timeout = timeout
        self._verify = verify
        self._follow = follow_redirects
        # TLS/HTTP2 fingerprint impersonation via curl_cffi — only if requested
        # AND the optional dependency is present (else transparently use httpx).
        self._impersonate = bool(impersonate) and _CURL_AVAILABLE
        self._imp_session = None
        # One egress list drives everything: an explicit pool, else the single
        # proxy, else direct-only.
        self._pool = ProxyPool(pool if pool else [proxy], rotation=rotation)
        # Lazily-built httpx client per distinct egress (proxy binds at build).
        self._clients: Dict[Optional[str], httpx.AsyncClient] = {}
        self.last_block: Optional[str] = None   # last WAF name seen, for callers

    def _client_for(self, proxy: Optional[str]) -> httpx.AsyncClient:
        c = self._clients.get(proxy)
        if c is None:
            c = httpx.AsyncClient(
                timeout=self._timeout,
                verify=self._verify,
                follow_redirects=self._follow,
                proxy=proxy,
            )
            self._clients[proxy] = c
        return c

    def _session(self):
        """The single curl_cffi session used for impersonated requests (proxy
        and impersonation target are passed per request)."""
        if self._imp_session is None:
            self._imp_session = _CurlSession()
        return self._imp_session

    @property
    def impersonating(self) -> bool:
        return self._impersonate

    @property
    def pool_status(self) -> list:
        return self._pool.status()

    async def __aenter__(self) -> "StealthClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()
        if self._imp_session is not None:
            try:
                await self._imp_session.close()
            except Exception:
                pass
            self._imp_session = None

    # Convenience verbs ------------------------------------------------------
    async def get(self, url: str, **kw) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> httpx.Response:
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw) -> httpx.Response:
        return await self.request("HEAD", url, **kw)

    def _headers_for(self, host: str, headers: Optional[Dict]) -> Dict[str, str]:
        """Merge the host's current browser identity with caller headers,
        keeping our User-Agent when stealth is active."""
        ua, base_headers = self._limiter.identity(host)
        if headers:
            merged = {**base_headers, **headers}
            if self._profile.rotate_identity:
                for k in list(merged):
                    if k.lower() == "user-agent":
                        merged.pop(k)
        else:
            merged = base_headers
        if self._profile.name != "off" or "user-agent" not in {k.lower() for k in merged}:
            merged["User-Agent"] = ua
        return merged

    @staticmethod
    def _caller_headers(headers: Optional[Dict]) -> Optional[Dict]:
        """Caller headers minus User-Agent — under impersonation, curl_cffi
        supplies the browser's UA/Accept/sec-ch-ua and header ordering itself,
        so we only pass request-specific extras (e.g. a spoofed Host)."""
        if not headers:
            return None
        return {k: v for k, v in headers.items() if k.lower() != "user-agent"}

    async def request(self, method: str, url: str, *, headers: Optional[Dict] = None, **kw) -> httpx.Response:
        host = urlparse(url).netloc
        retries = self._profile.max_retries
        last_exc: Optional[Exception] = None
        resp = None
        led = _current_ledger.get()   # active scan's attribution ledger, if any

        for attempt in range(retries + 1):
            # Identity + egress are resolved per attempt so a burn-and-rotate
            # on the previous try takes effect here.
            proxy = self._pool.for_host(host)
            imp_target = self._limiter.impersonate(host) if self._impersonate else None

            sem = await self._limiter.acquire(host)
            try:
                if self._impersonate:
                    resp = await self._session().request(
                        method, url,
                        headers=self._caller_headers(headers),
                        impersonate=imp_target,
                        proxy=proxy,
                        allow_redirects=self._follow,
                        verify=self._verify,
                        timeout=self._timeout,
                        **kw,
                    )
                else:
                    merged = self._headers_for(host, headers)
                    resp = await self._client_for(proxy).request(method, url, headers=merged, **kw)
            except _TRANSPORT_ERRORS as exc:
                last_exc = exc
                if led is not None:
                    led.record_request(host, proxy, imp_target)   # it still egressed
                self._pool.penalize(proxy)      # egress fault → bench + rotate
                self._pool.rotate_host(host)
                if attempt < retries:
                    if led is not None:
                        led.record_backoff()
                    await asyncio.sleep(self._backoff_delay(attempt))
                    continue
                raise
            finally:
                sem.release()

            if led is not None:
                led.record_request(host, proxy, imp_target)

            waf = looks_like_waf(resp)
            if resp.status_code in (429, 503) or waf:
                self.last_block = waf or f"http-{resp.status_code}"
                if led is not None:
                    led.record_block(self.last_block)
                cooldown = _retry_after_seconds(resp, self._profile.interval_cap)
                self._limiter.penalize(host, cooldown)
                # This egress got blocked on this host: burn it, swap to a fresh
                # proxy, and change identity so the retry looks like a new client.
                self._pool.penalize(proxy)
                self._pool.rotate_host(host)
                self._limiter.reroll_identity(host)
                if attempt < retries:
                    if led is not None:
                        led.record_backoff()
                    await asyncio.sleep(cooldown or self._backoff_delay(attempt))
                    continue
                return resp

            self._limiter.reward(host)
            self._pool.reward(proxy)
            return resp

        if resp is not None:
            return resp
        assert last_exc is not None
        raise last_exc

    @contextlib.asynccontextmanager
    async def stream(self, method: str, url: str, *, headers: Optional[Dict] = None, **kw):
        """Stealth-routed streaming request, so callers can size-cap or abort a
        body mid-flight (e.g. document downloads with a zip-bomb guard).

        Single attempt — no retry/rotate loop, since the caller owns the body.
        The request is proxied and carries the host's sticky browser identity +
        adaptive pacing; TLS/JA3 impersonation is *not* applied to streamed
        bodies (curl_cffi streaming differs), and the ledger records the request
        honestly as non-impersonated.
        """
        host = urlparse(url).netloc
        proxy = self._pool.for_host(host)
        led = _current_ledger.get()
        sem = await self._limiter.acquire(host)
        try:
            merged = self._headers_for(host, headers)
            async with self._client_for(proxy).stream(method, url, headers=merged, **kw) as resp:
                if led is not None:
                    led.record_request(host, proxy, None)
                # Body isn't read yet, so judge a block by status/headers only —
                # don't sniff resp.text (it would consume the stream).
                blocked = resp.status_code in (429, 503) or bool(resp.headers.get("cf-mitigated"))
                if blocked:
                    self.last_block = f"http-{resp.status_code}"
                    if led is not None:
                        led.record_block(self.last_block)
                    self._limiter.penalize(host, _retry_after_seconds(resp, self._profile.interval_cap))
                    self._pool.penalize(proxy)
                    self._pool.rotate_host(host)
                    self._limiter.reroll_identity(host)
                else:
                    self._limiter.reward(host)
                    self._pool.reward(proxy)
                yield resp
        finally:
            sem.release()

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential backoff with full jitter."""
        base = min(self._profile.interval_cap, (2 ** attempt) * 0.5)
        return random.uniform(0, base) + self._profile.base_interval


# ── Factory ──────────────────────────────────────────────────────────────────
def resolve_profile(config, override: Optional[str] = None) -> Profile:
    """Pick the active stealth profile from an explicit override, else config.

    ``scraper.stealth_profile`` names the profile directly; otherwise the
    long-standing ``evasive.enabled`` flag turns on 'quiet' (its jitter_range,
    if present, feeds the paranoid tuning). Defaults to 'off' — no behaviour
    change unless the operator opts in.
    """
    if override:
        name = override
    else:
        # scraper.stealth_profile is the fine control; a non-"off" value wins.
        # Otherwise the simple evasive.enabled on-switch raises "off" to "quiet".
        configured = config.get("scraper", "stealth_profile", default="off")
        if configured and configured != "off":
            name = configured
        elif config.get("evasive", "enabled", default=False):
            name = "quiet"
        else:
            name = "off"
    prof = PROFILES.get(name, PROFILES["off"])

    # Let a configured jitter_range widen the chosen profile's jitter.
    jr = config.get("evasive", "jitter_range", default=None)
    if jr and isinstance(jr, (list, tuple)) and len(jr) == 2 and prof.name != "off":
        prof = Profile(
            prof.name, prof.max_concurrency, prof.base_interval, prof.interval_cap,
            (float(jr[0]), float(jr[1])), prof.max_retries, prof.rotate_identity,
        )
    return prof


def resolve_egress(config, proxy=..., pool=...) -> Tuple[list, str]:
    """Resolve the egress list + rotation mode from config.

    Precedence: an explicit ``proxy_pool`` list wins; else the single
    ``scraper.proxy``; else direct-only. ``scraper.proxy_rotation`` selects
    sticky (per-host) or every (per-request) rotation.
    """
    if pool is ...:
        pool = config.get("scraper", "proxy_pool", default=None)
    if proxy is ...:
        proxy = config.get("scraper", "proxy", default=None) or None
    rotation = config.get("scraper", "proxy_rotation", default="sticky")

    if pool:
        # Keep None (direct) and real proxy URLs; drop only blank strings.
        egress = []
        for p in pool:
            if p is None:
                egress.append(None)
            elif str(p).strip():
                egress.append(str(p).strip())
        if not egress:
            egress = [proxy] if proxy else [None]
    elif proxy:
        egress = [proxy]
    else:
        egress = [None]
    return egress, rotation


def stealth_client(
    config,
    *,
    profile: Optional[str] = None,
    timeout: float = 30.0,
    verify: bool = False,
    follow_redirects: bool = True,
    proxy: Optional[str] = ...,  # sentinel: default to config
    pool: Optional[list] = ...,  # sentinel: default to config proxy_pool
    impersonate: Optional[bool] = None,  # None: default to config tls_impersonate
) -> StealthClient:
    """Construct a StealthClient using PhantomSignal config for defaults."""
    prof = resolve_profile(config, override=profile)
    egress, rotation = resolve_egress(config, proxy=proxy, pool=pool)
    if impersonate is None:
        impersonate = bool(config.get("scraper", "tls_impersonate", default=False))
    if impersonate and not _CURL_AVAILABLE:
        logger.warning("tls_impersonate is on but curl_cffi is not installed; "
                       "falling back to standard TLS. Run: pip install curl_cffi")
        impersonate = False
    return StealthClient(
        profile=prof,
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        pool=egress,
        rotation=rotation,
        impersonate=impersonate,
    )
