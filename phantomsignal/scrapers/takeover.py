"""
PhantomSignal Subdomain Takeover Detection — Dangling Claim Hunter

Phase 2. An *active* detector: it takes the CNAME'd subdomains surfaced by the
passive enumerator, matches each CNAME against a can-i-take-over-xyz-style
fingerprint database, and then confirms by (a) fetching the host's HTTP response
and matching the provider's "unclaimed" fingerprint and/or (b) checking whether
the CNAME target itself is unregistered (NXDOMAIN). Findings are graded:
confirmed-vulnerable vs. candidate-needs-review.

Design: the fingerprint DB and the match/classify logic are pure and unit-tested;
network I/O (enumeration reuse, HTTP fetch, NXDOMAIN check) lives in the class.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional

from phantomsignal.core.http import stealth_client

try:
    import dns.resolver
except Exception:  # pragma: no cover
    dns = None  # type: ignore

logger = logging.getLogger("phantomsignal.scrapers.takeover")

# Subset of the can-i-take-over-xyz fingerprint database.
#   cname       — substrings that identify the provider from the CNAME target
#   fingerprints— body strings shown when the resource is unclaimed
#   nxdomain    — if True, an NXDOMAIN on the CNAME target is itself the signal
#   status      — "vulnerable" (known-takeover-able) or "edge" (situational)
FINGERPRINT_DB = [
    {"service": "GitHub Pages", "cname": ["github.io"],
     "fingerprints": ["There isn't a GitHub Pages site here",
                      "For root URLs (like http://example.com/) you must provide an index.html file"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Heroku", "cname": ["herokuapp.com", "herokudns.com", "herokussl.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "AWS S3", "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Fastly", "cname": ["fastly.net"],
     "fingerprints": ["Fastly error: unknown domain"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Shopify", "cname": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable"],
     "nxdomain": False, "status": "edge"},
    {"service": "Bitbucket", "cname": ["bitbucket.io"],
     "fingerprints": ["Repository not found"],
     "nxdomain": True, "status": "vulnerable"},
    {"service": "Ghost", "cname": ["ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Pantheon", "cname": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek",
                      "404 error unknown site!"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Tumblr", "cname": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
     "nxdomain": False, "status": "edge"},
    {"service": "WordPress", "cname": ["wordpress.com"],
     "fingerprints": ["Do you want to register"],
     "nxdomain": False, "status": "edge"},
    {"service": "Surge.sh", "cname": ["surge.sh"],
     "fingerprints": ["project not found"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Zendesk", "cname": ["zendesk.com"],
     "fingerprints": ["Help Center Closed"],
     "nxdomain": False, "status": "edge"},
    {"service": "Read the Docs", "cname": ["readthedocs.io"],
     "fingerprints": ["unknown to Read the Docs"],
     "nxdomain": False, "status": "vulnerable"},
    {"service": "Azure", "cname": ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
                                   "trafficmanager.net", "blob.core.windows.net",
                                   "azureedge.net", "azure-api.net"],
     "fingerprints": [], "nxdomain": True, "status": "vulnerable"},
    {"service": "AWS Elastic Beanstalk", "cname": ["elasticbeanstalk.com"],
     "fingerprints": [], "nxdomain": True, "status": "vulnerable"},
]


# ── pure logic (unit-tested) ────────────────────────────────────────────────

def match_service(cname: str, db: Optional[List[Dict]] = None) -> Optional[Dict]:
    """Return the fingerprint DB entry whose CNAME pattern matches, else None."""
    db = db if db is not None else FINGERPRINT_DB
    if not cname:
        return None
    target = cname.strip().lower().rstrip(".")
    for entry in db:
        if any(pat in target for pat in entry["cname"]):
            return entry
    return None


def body_indicates_takeover(body: str, entry: Dict) -> bool:
    """True if the HTTP body contains any of the provider's unclaimed fingerprints."""
    if not body or not entry.get("fingerprints"):
        return False
    low = body.lower()
    return any(fp.lower() in low for fp in entry["fingerprints"])


def classify(entry: Dict, body_match: bool, target_nxdomain: bool) -> Optional[Dict]:
    """
    Grade a candidate into a finding, or None if there's no signal.

    Returns dict with: verdict (vulnerable|candidate), severity, confidence, reason.
    """
    # Strongest: the provider's unclaimed-resource fingerprint is present.
    if body_match:
        return {"verdict": "vulnerable", "severity": "high", "confidence": 0.9,
                "reason": f"{entry['service']} unclaimed-resource fingerprint in HTTP body"}
    # For nxdomain-type providers the signal *is* a dangling (unregistered)
    # target; if it still resolves the resource is claimed and live, so we emit
    # nothing rather than flag every live host on that provider.
    if entry.get("nxdomain"):
        if target_nxdomain:
            return {"verdict": "vulnerable", "severity": "high", "confidence": 0.85,
                    "reason": f"CNAME points to {entry['service']} and target is unregistered (NXDOMAIN)"}
        return None
    # Fingerprint-type, takeover-prone provider but body not confirmed (e.g. the
    # fetch failed) — surface as a candidate for manual review.
    if entry.get("status") == "vulnerable":
        return {"verdict": "candidate", "severity": "medium", "confidence": 0.5,
                "reason": f"CNAME points to takeover-prone service {entry['service']}; not confirmed"}
    return None


# ── detector ────────────────────────────────────────────────────────────────

class TakeoverDetector:
    """Active subdomain-takeover detection over a domain's CNAME'd subdomains."""

    def __init__(self, config):
        self.config = config
        if dns is not None:
            self._resolver = dns.resolver.Resolver()
            self._resolver.timeout = 2
            self._resolver.lifetime = 3
        else:  # pragma: no cover
            self._resolver = None

    async def run(self, target: str) -> List[Dict]:
        from phantomsignal.scrapers.subdomain_enum import SubdomainEnumerator

        enum = SubdomainEnumerator(self.config)
        domain = enum._extract_domain(target)
        if not domain:
            return []

        sub_results = await enum.run(domain)
        # Collect (host, cname) pairs that point at a known takeover-able provider.
        candidates = []
        for r in sub_results:
            if r.get("type") != "subdomain":
                continue
            host = r["data"].get("subdomain")
            for cname in r["data"].get("cnames", []) or []:
                entry = match_service(cname)
                if entry:
                    candidates.append((host, cname, entry))

        if not candidates:
            logger.info("No CNAMEs pointing to takeover-prone services for %s", domain)
            return []

        logger.info("Analyzing %d takeover candidate(s) for %s", len(candidates), domain)
        findings = await asyncio.gather(
            *(self._analyze(host, cname, entry) for host, cname, entry in candidates),
            return_exceptions=True,
        )
        return [f for f in findings if isinstance(f, dict)]

    async def _analyze(self, host: str, cname: str, entry: Dict) -> Optional[Dict]:
        body_match = False
        if entry.get("fingerprints"):
            body = await self._fetch_body(host)
            body_match = body_indicates_takeover(body, entry)

        target_nxdomain = False
        if entry.get("nxdomain"):
            target_nxdomain = await self._is_nxdomain(cname)

        verdict = classify(entry, body_match, target_nxdomain)
        if not verdict:
            return None

        vulnerable = verdict["verdict"] == "vulnerable"
        return {
            "type": "takeover_vulnerable" if vulnerable else "takeover_candidate",
            "source": "takeover",
            "data": {
                "subdomain": host,
                "cname": cname,
                "service": entry["service"],
                "verdict": verdict["verdict"],
                "severity": verdict["severity"],
                "reason": verdict["reason"],
            },
            "confidence": verdict["confidence"],
            "relevance_score": 0.95 if vulnerable else 0.7,
            "tags": ["takeover", "dns", entry["service"].lower().replace(" ", "-")]
            + (["vulnerable"] if vulnerable else ["candidate"]),
            "is_anomaly": vulnerable,
        }

    async def _fetch_body(self, host: str) -> str:
        for scheme in ("https", "http"):
            try:
                async with stealth_client(
                    self.config, timeout=8, follow_redirects=True,
                ) as client:
                    resp = await client.get(f"{scheme}://{host}")
                    return resp.text or ""
            except Exception as e:
                logger.debug("fetch %s://%s failed: %s", scheme, host, e)
        return ""

    async def _is_nxdomain(self, target: str) -> bool:
        if self._resolver is None or dns is None:
            return False
        loop = asyncio.get_event_loop()

        def _check() -> bool:
            try:
                self._resolver.resolve(target, "A")
                return False
            except dns.resolver.NXDOMAIN:
                return True
            except Exception:
                return False

        return await loop.run_in_executor(None, _check)
