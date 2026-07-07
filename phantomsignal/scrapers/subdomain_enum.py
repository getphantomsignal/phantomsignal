"""
PhantomSignal Passive Subdomain Enumeration — Surface Mapping at Scale

Phase 2 of the modernization roadmap. Where dns_recon does a small brute-force
+ crt.sh, this module gathers subdomains from several *passive* sources that
need no API keys, generates permutations, filters wildcard DNS false positives,
and resolve-validates the survivors. Results carry resolved A records and CNAMEs
so they feed both the recursive pivot engine and the subdomain-takeover
signature (Phase 1).

Design: network I/O lives in the SubdomainEnumerator class; the parsing,
permutation, merge, and wildcard-classification logic are module-level pure
functions so they can be unit-tested without hitting the network or DNS.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import json as _json
import logging
import random
import re
import string
from typing import Dict, Iterable, List, Optional, Set, Tuple

import httpx

try:
    import dns.resolver
except Exception:  # pragma: no cover - dnspython is a declared dependency
    dns = None  # type: ignore

logger = logging.getLogger("phantomsignal.scrapers.subdomain_enum")

# Labels used to build permutations off already-known subdomains.
PERMUTATION_WORDS = [
    "dev", "staging", "stage", "test", "qa", "uat", "prod", "preprod",
    "api", "admin", "internal", "int", "vpn", "mail", "smtp", "portal",
    "app", "web", "cdn", "assets", "static", "beta", "demo", "sandbox",
    "gateway", "gw", "auth", "sso", "git", "jenkins", "grafana", "kibana",
]

# Cap total candidate hosts before resolution so permutations can't explode.
MAX_CANDIDATES = 1500

_HOST_RE = re.compile(r"^(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


# ── pure helpers (unit-tested) ─────────────────────────────────────────────

def normalize_host(host: str) -> Optional[str]:
    """Lowercase, strip wildcard/port/scheme, validate. Return None if invalid."""
    if not host or not isinstance(host, str):
        return None
    h = host.strip().lower().rstrip(".")
    h = h.split("://", 1)[-1]          # drop scheme if present
    h = h.split("/", 1)[0]             # drop path
    h = h.split(":", 1)[0]             # drop port
    if h.startswith("*."):
        h = h[2:]
    if not h or not _HOST_RE.match(h):
        return None
    return h


def merge_hosts(domain: str, *host_sets: Iterable[str]) -> Set[str]:
    """Normalize every candidate and keep only in-scope hosts under ``domain``."""
    domain = domain.lower().rstrip(".")
    suffix = f".{domain}"
    out: Set[str] = set()
    for hs in host_sets:
        for raw in hs or []:
            norm = normalize_host(raw)
            if norm and (norm == domain or norm.endswith(suffix)):
                out.add(norm)
    return out


def generate_permutations(domain: str, known: Iterable[str],
                          words: Optional[List[str]] = None) -> Set[str]:
    """
    Build candidate hostnames by permuting the leftmost label of each known
    subdomain with a wordlist (prefix and suffix) plus numeric variants.
    """
    words = words or PERMUTATION_WORDS
    domain = domain.lower().rstrip(".")
    suffix = f".{domain}"
    out: Set[str] = set()

    # base labels: the sub-part of each known host, plus the wordlist itself
    bases: Set[str] = set()
    for host in known:
        if host == domain:
            continue
        if host.endswith(suffix):
            sub = host[: -len(suffix)]
            first = sub.split(".")[0]
            if first:
                bases.add(first)
    bases |= set(words)

    for base in bases:
        out.add(f"{base}{suffix}")
        for w in words:
            out.add(f"{w}-{base}{suffix}")
            out.add(f"{base}-{w}{suffix}")
        for n in range(1, 4):
            out.add(f"{base}{n}{suffix}")
    # keep only validly-formed hosts
    return {h for h in out if normalize_host(h)}


def parse_crtsh(payload) -> Set[str]:
    """crt.sh JSON → set of name_value hosts (may contain newline-joined SANs)."""
    hosts: Set[str] = set()
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return hosts
    for entry in payload or []:
        name = (entry or {}).get("name_value", "")
        for line in str(name).splitlines():
            n = normalize_host(line)
            if n:
                hosts.add(n)
    return hosts


def parse_hackertarget(text: str) -> Set[str]:
    """HackerTarget hostsearch → 'host,ip' lines."""
    hosts: Set[str] = set()
    if not text or "error" in text.lower():
        return hosts
    for line in text.splitlines():
        host = line.split(",", 1)[0]
        n = normalize_host(host)
        if n:
            hosts.add(n)
    return hosts


def parse_alienvault(payload) -> Set[str]:
    """AlienVault OTX passive DNS → hostname records."""
    hosts: Set[str] = set()
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return hosts
    for rec in (payload or {}).get("passive_dns", []) or []:
        n = normalize_host((rec or {}).get("hostname", ""))
        if n:
            hosts.add(n)
    return hosts


def parse_anubis(payload) -> Set[str]:
    """jldc.me Anubis DB → flat JSON list of hostnames."""
    hosts: Set[str] = set()
    if isinstance(payload, str):
        try:
            payload = _json.loads(payload)
        except Exception:
            return hosts
    for item in payload or []:
        n = normalize_host(item)
        if n:
            hosts.add(n)
    return hosts


def is_wildcard_false_positive(ips: Iterable[str], cnames: Iterable[str],
                               wildcard_ips: Set[str]) -> bool:
    """
    A host is a wildcard artifact when it has no CNAME and every IP it resolves
    to is part of the domain's wildcard answer set. A CNAME means it's a real,
    explicitly-configured record (and the takeover-relevant case), so keep it.
    """
    if cnames:
        return False
    ipset = {i for i in ips if i}
    if not ipset or not wildcard_ips:
        return False
    return ipset.issubset(wildcard_ips)


# ── enumerator ─────────────────────────────────────────────────────────────

class SubdomainEnumerator:
    """Passive multi-source subdomain enumeration with wildcard filtering."""

    def __init__(self, config):
        self.config = config
        self._resolve_sem = asyncio.Semaphore(150)
        if dns is not None:
            self._resolver = dns.resolver.Resolver()
            # Tuned for bulk candidate resolution: fail fast, resolve wide.
            self._resolver.timeout = 2
            self._resolver.lifetime = 3
        else:  # pragma: no cover
            self._resolver = None

    async def run(self, target: str) -> List[Dict]:
        domain = self._extract_domain(target)
        if not domain:
            return []
        logger.info("Passive subdomain enumeration for %s", domain)

        passive, source_counts = await self._gather_passive(domain)
        candidates = merge_hosts(domain, passive)
        perms = generate_permutations(domain, candidates)
        candidates |= perms

        if len(candidates) > MAX_CANDIDATES:
            logger.info("Capping candidates %d → %d", len(candidates), MAX_CANDIDATES)
            candidates = set(list(candidates)[:MAX_CANDIDATES])

        wildcard_ips = await self._detect_wildcard(domain)
        resolved = await self._resolve_all(candidates, wildcard_ips)

        return self._build_results(domain, resolved, source_counts,
                                   candidate_count=len(candidates),
                                   wildcard=bool(wildcard_ips))

    # ── passive sources ────────────────────────────────────────────────────

    async def _gather_passive(self, domain: str) -> Tuple[Set[str], Dict[str, int]]:
        async with httpx.AsyncClient(
            timeout=20, follow_redirects=True,
            headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
        ) as client:
            sources = {
                "crt.sh": self._src_crtsh(client, domain),
                "hackertarget": self._src_hackertarget(client, domain),
                "alienvault": self._src_alienvault(client, domain),
                "anubis": self._src_anubis(client, domain),
            }
            gathered = await asyncio.gather(*sources.values(), return_exceptions=True)

        merged: Set[str] = set()
        counts: Dict[str, int] = {}
        for name, res in zip(sources.keys(), gathered):
            if isinstance(res, Exception):
                logger.debug("source %s failed: %s", name, res)
                counts[name] = 0
                continue
            hosts = merge_hosts(domain, res)
            counts[name] = len(hosts)
            merged |= hosts
        return merged, counts

    async def _src_crtsh(self, client, domain) -> Set[str]:
        r = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")
        return parse_crtsh(r.json()) if r.status_code == 200 else set()

    async def _src_hackertarget(self, client, domain) -> Set[str]:
        r = await client.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        return parse_hackertarget(r.text) if r.status_code == 200 else set()

    async def _src_alienvault(self, client, domain) -> Set[str]:
        r = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns")
        return parse_alienvault(r.json()) if r.status_code == 200 else set()

    async def _src_anubis(self, client, domain) -> Set[str]:
        r = await client.get(f"https://jldc.me/anubis/subdomains/{domain}")
        return parse_anubis(r.json()) if r.status_code == 200 else set()

    # ── DNS resolution / wildcard ────────────────────────────────────────────

    def _resolve(self, fqdn: str, rtype: str) -> List[str]:
        if self._resolver is None:
            return []
        try:
            return [str(r) for r in self._resolver.resolve(fqdn, rtype)]
        except Exception:
            return []

    async def _detect_wildcard(self, domain: str) -> Set[str]:
        """Resolve random hosts; any IPs they answer with are the wildcard set."""
        wildcard: Set[str] = set()
        loop = asyncio.get_event_loop()
        for _ in range(3):
            rand = "".join(random.choices(string.ascii_lowercase, k=16))
            ips = await loop.run_in_executor(None, self._resolve, f"{rand}.{domain}", "A")
            wildcard.update(ips)
        if wildcard:
            logger.info("Wildcard DNS detected for %s: %s", domain, sorted(wildcard))
        return wildcard

    async def _resolve_one(self, fqdn: str, wildcard_ips: Set[str]) -> Optional[Dict]:
        async with self._resolve_sem:
            loop = asyncio.get_event_loop()
            ips = await loop.run_in_executor(None, self._resolve, fqdn, "A")
            cnames = await loop.run_in_executor(None, self._resolve, fqdn, "CNAME")
            if not ips and not cnames:
                return None
            if is_wildcard_false_positive(ips, cnames, wildcard_ips):
                return None
            return {"subdomain": fqdn, "ips": ips, "cnames": cnames}

    async def _resolve_all(self, candidates: Set[str],
                           wildcard_ips: Set[str]) -> List[Dict]:
        tasks = [self._resolve_one(c, wildcard_ips) for c in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, dict)]

    # ── result assembly ──────────────────────────────────────────────────────

    def _build_results(self, domain: str, resolved: List[Dict],
                       source_counts: Dict[str, int], candidate_count: int,
                       wildcard: bool) -> List[Dict]:
        results: List[Dict] = []
        for rec in sorted(resolved, key=lambda r: r["subdomain"]):
            tags = ["dns", "subdomain", "passive"]
            if rec["cnames"]:
                tags.append("cname")
            results.append({
                "type": "subdomain",
                "source": "subdomain_enum",
                "data": {**rec, "domain": domain},
                "confidence": 1.0,
                "relevance_score": 0.78,
                "tags": tags,
            })
        results.append({
            "type": "subdomain_summary",
            "source": "subdomain_enum",
            "data": {
                "domain": domain,
                "discovered_count": len(resolved),
                "candidates_tested": candidate_count,
                "wildcard_dns": wildcard,
                "sources": source_counts,
                "subdomains": [r["subdomain"] for r in resolved],
            },
            "confidence": 1.0,
            "relevance_score": 0.85,
            "tags": ["dns", "subdomain", "summary", "passive"],
        })
        return results

    def _extract_domain(self, target: str) -> Optional[str]:
        t = (target or "").strip().lower()
        t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        t = t.split("@")[-1]  # tolerate an email target
        return t if t and _HOST_RE.match(t) else None
