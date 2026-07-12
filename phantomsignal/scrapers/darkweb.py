"""
PhantomSignal Dark-Web Monitor — Leak Exposure Tracking

Phase 4 (identity / dark web). Defensive exposure monitoring for an authorized
target: does the org appear on a ransomware leak site? This is part 1 — keyless,
clearnet, high-signal (>50% of modern breaches surface on leak sites). Part 2
adds Tor .onion crawling, paste sweeps, and stealer-log correlation.

Guardrails (enforced here and by design for part 2):
  • target-scoped — results are filtered to the authorized target, not bulk data.
  • no credential store — we report the FACT of exposure; any credential-shaped
    value is redacted via mask_secret() (never store/emit plaintext secrets).

Source: ransomware.live v2 API (keyless). Design: HTTP I/O in the class; parsing,
target-scoping, and masking are pure module-level functions with unit tests.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import logging
import re
import socket
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

logger = logging.getLogger("phantomsignal.scrapers.darkweb")

RANSOMWARE_API = "https://api.ransomware.live/v2"

_HOST_RE = re.compile(r"^(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
# email[:;|]password  (password captured lazily but masked before it leaves)
_COMBO_EMAIL_RE = re.compile(r"^([^\s:;|]+@[^\s:;|]+)[:;|](.+)$")


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def mask_secret(value: str) -> str:
    """
    Redact a credential-shaped value: report only that a secret exists and its
    length, never any plaintext. Used for stolen-credential exposure so the tool
    stays a breach-EXPOSURE monitor, not a credential store.
    """
    if not value:
        return ""
    # No square brackets — they collide with the CLI's Rich markup and vanish.
    return f"redacted({len(str(value))})"


def extract_domain(target: str) -> Optional[str]:
    t = (target or "").strip().lower()
    t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
    return t if t and _HOST_RE.match(t) else None


def registered_name(domain: str) -> str:
    """Second-level label used as the leak-site search query (eTLD+1 minus suffix)."""
    try:
        import tldextract
        ext = tldextract.extract(domain)
        if ext.domain:
            return ext.domain.lower()
    except Exception:
        pass
    parts = (domain or "").lower().split(".")
    return parts[-2] if len(parts) >= 2 else (domain or "").lower()


def parse_ransomware_victims(payload) -> List[Dict]:
    """Normalize ransomware.live v2 victim records to the fields we surface."""
    if not isinstance(payload, list):
        return []
    out: List[Dict] = []
    for rec in payload:
        if not isinstance(rec, dict):
            continue
        out.append({
            "victim": (rec.get("victim") or "").strip(),
            "group": (rec.get("group") or "").strip(),
            "domain": (rec.get("domain") or "").strip().lower(),
            "attack_date": rec.get("attackdate") or "",
            "discovered": rec.get("discovered") or "",
            "country": rec.get("country") or "",
            "activity": rec.get("activity") or "",
            "claim_url": rec.get("claim_url") or "",
            "record_url": rec.get("url") or "",
            "infostealer": bool(rec.get("infostealer")),
        })
    return out


def _is_junk_victim(name: str) -> bool:
    """A real org name never contains HTML/markup artifacts — ransomware.live
    occasionally scrapes such fragments; they must not drive a name match."""
    return (not name) or any(c in name for c in "<>=")


def victim_matches_target(record: Dict, domain: str) -> Optional[str]:
    """
    Scope a fuzzy leak-site hit to the authorized target. Returns the match
    strength ("domain" | "name") or None. Domain match is reliable; name match is
    advisory (fuzzy search on a common brand is noisy), and junk victim strings
    are rejected. The searchvictims endpoint fuzzy-matches names, so we confirm
    the hit actually concerns this target before reporting.
    """
    dom = (domain or "").lower()
    sld = registered_name(dom)
    rec_domain = (record.get("domain") or "").lower()
    if rec_domain and (rec_domain == dom or rec_domain.endswith("." + dom) or dom.endswith("." + rec_domain)):
        return "domain"
    victim = (record.get("victim") or "").lower()
    if _is_junk_victim(victim):
        return None
    if sld and len(sld) >= 3 and re.search(rf"\b{re.escape(sld)}\b", victim):
        return "name"
    return None


def _host_in_scope(host: str, domain: str) -> bool:
    host = (host or "").lower().split(":", 1)[0]      # drop any :port
    return bool(host) and (host == domain or host.endswith("." + domain))


def parse_combolist(text: str, domain: str) -> List[Dict]:
    """
    Correlate a stealer-log / combolist dump to the authorized target. Handles
    ``email:password`` (also ``;`` / ``|``) and stealer ULP ``URL:login:password``
    lines. Returns only records that concern ``domain`` — either a corporate
    address (``…@domain``) or a credential FOR the target's service (URL host in
    scope). PASSWORDS ARE ALWAYS MASKED before they leave this function; plaintext
    secrets are never stored or emitted. Pure and network-free.
    """
    dom = (domain or "").lower()
    if not dom:
        return []
    out: List[Dict] = []
    seen: set = set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or len(line) > 4000:
            continue
        rec = _parse_combo_line(line, dom)
        if rec:
            key = (rec["kind"], rec["identity"], rec.get("host", ""))
            if key not in seen:
                seen.add(key)
                out.append(rec)
    return out


def _parse_combo_line(line: str, dom: str) -> Optional[Dict]:
    low = line.lower()
    if low.startswith(("http://", "https://")):        # stealer ULP: URL:login:pass
        try:
            url, login, password = line.rsplit(":", 2)
        except ValueError:
            return None
        host = urlparse(url).netloc.lower()
        login_dom = login.split("@", 1)[1].lower() if "@" in login else ""
        if _host_in_scope(host, dom) or _host_in_scope(login_dom, dom):
            return {"kind": "service_credential", "identity": login.strip(),
                    "host": host, "url": url, "password": mask_secret(password)}
        return None
    m = _COMBO_EMAIL_RE.match(line)                     # email:password
    if m:
        email, password = m.group(1), m.group(2)
        edom = email.split("@", 1)[1].lower()
        if _host_in_scope(edom, dom):
            return {"kind": "corporate_credential", "identity": email.lower(),
                    "host": edom, "url": "", "password": mask_secret(password)}
    return None


def tor_available(proxy: str = "socks5://127.0.0.1:9050") -> bool:
    """True only if the SOCKS transport is installed AND the Tor proxy accepts a
    connection — so onion enrichment degrades cleanly instead of erroring."""
    try:
        import socksio  # noqa: F401  (httpx needs this for socks proxies)
    except Exception:
        return False
    p = urlparse(proxy)
    try:
        with socket.create_connection((p.hostname or "127.0.0.1", p.port or 9050), timeout=3):
            return True
    except Exception:
        return False


class DarkWebMonitor:
    """Keyless, clearnet leak-exposure monitoring for an authorized target."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("darkweb", "timeout", default=20)
        self.max_results = config.get("darkweb", "max_results", default=50)
        # Stealer-log / combolist correlation: caller-supplied dump files.
        self.combolist_paths = config.get("darkweb", "combolist_paths", default=None) or []
        self.max_combolist_mb = config.get("darkweb", "max_combolist_mb", default=200)
        # Tor .onion enrichment of ransomware claim URLs (opt-in, degrades if no Tor).
        self.tor_enrich = config.get("darkweb", "tor_enrich", default=False)
        self.tor_proxy = config.get("darkweb", "tor_proxy", default="socks5://127.0.0.1:9050")

    async def run(self, target: str) -> List[Dict]:
        domain = extract_domain(target)
        if not domain:
            return []
        matches = await self._ransomware_leaks(domain)
        results = self._build_results(domain, matches)
        results.extend(self._correlate_combolists(domain))
        results.extend(await self._tor_enrich_onions(domain, matches))
        return results

    def _correlate_combolists(self, domain: str) -> List[Dict]:
        """Correlate configured stealer-log/combolist dumps to the target.
        Passwords are masked by parse_combolist before they reach here."""
        if not self.combolist_paths:
            return []
        cap = int(self.max_combolist_mb) * 1024 * 1024
        results: List[Dict] = []
        for path in self.combolist_paths:
            try:
                p = Path(path)
                if not p.is_file() or p.stat().st_size > cap:
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                logger.debug("could not read combolist %s: %s", path, exc)
                continue
            for rec in parse_combolist(text, domain):
                results.append({
                    "type": "credential_exposure",
                    "source": "darkweb",
                    "data": {
                        "target": domain,
                        "kind": rec["kind"],       # corporate_ or service_credential
                        "identity": rec["identity"],
                        "host": rec["host"],
                        "url": rec["url"],
                        "password": rec["password"],   # already "[redacted:N]"
                        "dump": p.name,
                    },
                    "confidence": 0.9,
                    "relevance_score": 0.95,
                    "tags": ["darkweb", "stealer", "credential", "exposure"],
                    "is_anomaly": True,
                })
        return results

    async def _tor_enrich_onions(self, domain: str, matches: List[Dict]) -> List[Dict]:
        """Optionally reach ransomware claim .onion URLs over Tor. Degrades to a
        single 'unavailable' note when Tor/SOCKS isn't present (no hard failure)."""
        onions = [m["claim_url"] for m in matches
                  if m.get("claim_url", "").lower().endswith(".onion")
                  or ".onion" in m.get("claim_url", "").lower()]
        if not self.tor_enrich or not onions:
            return []
        if not tor_available(self.tor_proxy):
            return [{
                "type": "tor_unavailable", "source": "darkweb",
                "data": {"target": domain, "onion_urls": len(onions),
                         "reason": "Tor SOCKS proxy not reachable (or socksio not installed) "
                                   "— onion enrichment skipped"},
                "confidence": 1.0, "relevance_score": 0.3,
                "tags": ["darkweb", "tor", "unavailable"],
            }]

        results: List[Dict] = []
        async with httpx.AsyncClient(timeout=self.timeout, proxy=self.tor_proxy,
                                     follow_redirects=True) as client:
            for url in onions[:self.max_results]:
                reachable = False
                try:
                    r = await client.get(url)
                    reachable = r.status_code < 500
                except Exception:
                    reachable = False
                results.append({
                    "type": "onion_reachable", "source": "darkweb",
                    "data": {"target": domain, "claim_url": url, "reachable": reachable},
                    "confidence": 0.9, "relevance_score": 0.6,
                    "tags": ["darkweb", "tor", "onion"],
                })
        return results

    async def _ransomware_leaks(self, domain: str) -> List[Dict]:
        query = registered_name(domain)
        if not query:
            return []
        url = f"{RANSOMWARE_API}/searchvictims/{quote(query)}"
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True,
                headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
            ) as client:
                r = await client.get(url)
                payload = r.json() if r.status_code == 200 else []
        except Exception as exc:
            logger.debug("ransomware.live query failed for %s: %s", domain, exc)
            return []

        scoped: List[Dict] = []
        for rec in parse_ransomware_victims(payload):
            strength = victim_matches_target(rec, domain)
            if strength:
                rec["match"] = strength
                scoped.append(rec)
        return scoped[:self.max_results]

    def _build_results(self, domain: str, matches: List[Dict]) -> List[Dict]:
        results: List[Dict] = []
        for rec in matches:
            results.append({
                "type": "ransomware_exposure",
                "source": "darkweb",
                "data": {
                    "target": domain,
                    "victim": rec["victim"],
                    "group": rec["group"],
                    "attack_date": rec["attack_date"],
                    "discovered": rec["discovered"],
                    "country": rec["country"],
                    "activity": rec["activity"],
                    "claim_url": rec["claim_url"],
                    "record_url": rec["record_url"],
                    "has_infostealer_data": rec["infostealer"],
                    "match": rec["match"],
                },
                # a domain-confirmed leak is near-certain; a name match is weaker
                "confidence": 0.95 if rec["match"] == "domain" else 0.6,
                "relevance_score": 1.0 if rec["match"] == "domain" else 0.7,
                "tags": ["darkweb", "ransomware", "leak", "breach"],
                # only a domain-confirmed hit is a real alert; a fuzzy name match
                # is advisory and must not raise a false anomaly.
                "is_anomaly": rec["match"] == "domain",
            })

        results.append({
            "type": "darkweb_summary",
            "source": "darkweb",
            "data": {
                "target": domain,
                "ransomware_hits": len(matches),
                "domain_confirmed": sum(1 for m in matches if m["match"] == "domain"),
                "name_matches": sum(1 for m in matches if m["match"] == "name"),
                "groups": sorted({m["group"] for m in matches if m["group"]}),
                "sources_checked": ["ransomware.live"]
                + (["combolists"] if self.combolist_paths else []),
            },
            "confidence": 1.0,
            "relevance_score": 0.8 if matches else 0.4,
            "tags": ["darkweb", "summary"],
            # a confirmed leak is the alert; name-only fuzzy hits don't raise one
            "is_anomaly": any(m["match"] == "domain" for m in matches),
        })
        return results
