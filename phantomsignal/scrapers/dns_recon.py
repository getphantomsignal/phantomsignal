"""
PhantomSignal DNS Recon — Mapping the Shadow Network
Full DNS enumeration: records, zone transfer, subdomain brute-force.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

import dns.resolver
import dns.zone
import dns.query
import dns.message
import dns.flags
import dns.name
import dns.rdatatype
import httpx

logger = logging.getLogger("phantomsignal.dns_recon")


# ── pure helpers (unit-tested) ──────────────────────────────────────────────

def hosts_in_24(ip: str) -> List[str]:
    """Every host address in the /24 containing ``ip`` (network + broadcast trimmed)."""
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
    except ValueError:
        return []
    return [str(h) for h in net.hosts()]


def nsec_walk_names(next_of, domain: str, max_steps: int = 500) -> set:
    """
    Pure NSEC zone-walk driver. ``next_of(name)`` returns the NSEC `next` owner
    after ``name`` (or None to stop). Terminates on wrap-to-apex, a repeat, or the
    step bound. Returns the in-zone names discovered. Network-free → unit-tested.
    """
    found: set = set()
    current = domain
    for _ in range(max_steps):
        nxt = next_of(current)
        if not nxt or nxt == domain or nxt in found:
            break
        if nxt.endswith("." + domain):
            found.add(nxt)
        current = nxt
    return found


# Third-party domains probed for cache snooping — presence in a resolver's cache
# implies someone behind it recently resolved them.
CACHE_SNOOP_PROBES = [
    "google.com", "facebook.com", "microsoft.com", "office365.com",
    "dropbox.com", "slack.com", "zoom.us", "salesforce.com", "okta.com",
    "github.com", "amazonaws.com", "cloudflare.com",
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "ns3",
    "api", "dev", "staging", "stage", "test", "beta", "alpha",
    "admin", "portal", "vpn", "remote", "secure", "shop", "store",
    "blog", "forum", "support", "help", "docs", "cdn", "static",
    "assets", "media", "img", "images", "video", "download",
    "mobile", "m", "app", "apps", "web", "www2", "old", "new",
    "internal", "intranet", "corp", "office", "extranet",
    "git", "gitlab", "github", "svn", "repo", "code",
    "jenkins", "ci", "cd", "build", "deploy",
    "db", "mysql", "postgres", "mongo", "redis", "elastic",
    "kibana", "grafana", "prometheus", "monitoring",
    "auth", "login", "sso", "oauth", "id", "identity",
    "smtp", "imap", "pop3", "mail2", "webmail",
    "backup", "bak", "archive", "data",
    "s3", "storage", "files", "upload",
    "search", "analytics", "tracking",
    "sandbox", "demo", "preview", "uat", "qa",
    "v2", "v3", "v4", "api2", "api-v2",
    "en", "es", "fr", "de", "pt", "ru", "cn", "jp",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "SRV", "PTR"]


class DNSRecon:
    """Full-spectrum DNS reconnaissance engine."""

    def __init__(self, config):
        self.config = config
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5

    async def run(self, target: str) -> List[Dict]:
        """Execute full DNS recon against a target domain."""
        domain = self._extract_domain(target)
        if not domain:
            return []

        results = []
        logger.info(f"DNS recon initiated for {domain}")

        tasks = [
            self._enumerate_records(domain),
            self._check_zone_transfer(domain),
            self._brute_subdomains(domain),
            self._check_certificate_transparency(domain),
            self._reverse_dns(domain),
            self._check_dnssec(domain),
            self._check_spf_dmarc(domain),
            self._nsec_walk(domain),
            self._ptr_sweep(domain),
            self._cache_snoop(domain),
        ]

        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for task_results in gathered:
            if isinstance(task_results, list):
                results.extend(task_results)
            elif isinstance(task_results, dict):
                results.append(task_results)

        return results

    async def _enumerate_records(self, domain: str) -> List[Dict]:
        """Enumerate all standard DNS record types."""
        results = []
        all_records = {}

        for rtype in RECORD_TYPES:
            try:
                loop = asyncio.get_event_loop()
                answers = await loop.run_in_executor(
                    None, self._query_record, domain, rtype
                )
                if answers:
                    all_records[rtype] = answers
            except Exception:
                pass

        if all_records:
            results.append({
                "type": "dns_records",
                "source": "dns_recon",
                "data": {
                    "domain": domain,
                    "records": all_records,
                    "record_types_found": list(all_records.keys()),
                },
                "confidence": 1.0,
                "relevance_score": 0.9,
                "tags": ["dns", "records"],
            })

        # Extract IPs from A records for pivot
        if "A" in all_records:
            for ip in all_records["A"]:
                results.append({
                    "type": "ip_address",
                    "source": "dns_recon",
                    "data": {"ip": ip, "domain": domain, "record_type": "A"},
                    "confidence": 1.0,
                    "relevance_score": 0.8,
                    "tags": ["ip", "dns", "a_record"],
                })

        return results

    def _query_record(self, domain: str, rtype: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, rtype)
            return [str(r) for r in answers]
        except Exception:
            return []

    async def _check_zone_transfer(self, domain: str) -> List[Dict]:
        """Attempt AXFR zone transfer against all NS servers."""
        results = []
        ns_servers = self._query_record(domain, "NS")

        for ns in ns_servers:
            ns = ns.rstrip(".")
            try:
                loop = asyncio.get_event_loop()
                zone = await asyncio.wait_for(
                    loop.run_in_executor(None, self._attempt_axfr, domain, ns),
                    timeout=10,
                )
                if zone:
                    results.append({
                        "type": "zone_transfer",
                        "source": "dns_recon",
                        "data": {
                            "domain": domain,
                            "nameserver": ns,
                            "vulnerable": True,
                            "records": zone,
                            "record_count": len(zone),
                        },
                        "confidence": 1.0,
                        "relevance_score": 1.0,
                        "tags": ["dns", "zone_transfer", "vulnerability", "critical"],
                        "is_anomaly": True,
                    })
            except Exception:
                pass

        return results

    def _attempt_axfr(self, domain: str, nameserver: str) -> Optional[List[str]]:
        try:
            ns_ip = socket.gethostbyname(nameserver)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name}.{domain} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}")
            return records if records else None
        except Exception:
            return None

    async def _brute_subdomains(self, domain: str) -> List[Dict]:
        """Brute-force subdomain enumeration."""
        results = []
        discovered = []

        semaphore = asyncio.Semaphore(50)
        tasks = [
            self._check_subdomain(f"{sub}.{domain}", semaphore)
            for sub in COMMON_SUBDOMAINS
        ]
        sub_results = await asyncio.gather(*tasks, return_exceptions=True)

        for sub, result in zip(COMMON_SUBDOMAINS, sub_results):
            if isinstance(result, dict) and result:
                discovered.append(result)
                results.append({
                    "type": "subdomain",
                    "source": "dns_recon",
                    "data": result,
                    "confidence": 1.0,
                    "relevance_score": 0.75,
                    "tags": ["dns", "subdomain", "enumeration"],
                })

        if discovered:
            results.append({
                "type": "subdomain_summary",
                "source": "dns_recon",
                "data": {
                    "domain": domain,
                    "discovered_count": len(discovered),
                    "subdomains": [d["subdomain"] for d in discovered],
                },
                "confidence": 1.0,
                "relevance_score": 0.85,
                "tags": ["dns", "subdomain", "summary"],
            })

        return results

    async def _check_subdomain(
        self, fqdn: str, semaphore: asyncio.Semaphore
    ) -> Optional[Dict]:
        async with semaphore:
            try:
                loop = asyncio.get_event_loop()
                ips = await loop.run_in_executor(None, self._query_record, fqdn, "A")
                if ips:
                    return {
                        "subdomain": fqdn,
                        "ips": ips,
                        "cnames": self._query_record(fqdn, "CNAME"),
                    }
            except Exception:
                pass
            return None

    async def _check_certificate_transparency(self, domain: str) -> List[Dict]:
        """Query crt.sh for certificate transparency logs — reveals subdomains."""
        results = []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "PhantomSignal OSINT Framework"},
                )
                if response.status_code == 200:
                    certs = response.json()
                    seen_names = set()
                    subdomains = []

                    for cert in certs:
                        names = cert.get("name_value", "").split("\n")
                        for name in names:
                            name = name.strip().lower().lstrip("*.")
                            if name and name not in seen_names and domain in name:
                                seen_names.add(name)
                                subdomains.append({
                                    "name": name,
                                    "issuer": cert.get("issuer_name", ""),
                                    "not_before": cert.get("not_before"),
                                    "not_after": cert.get("not_after"),
                                })

                    if subdomains:
                        results.append({
                            "type": "cert_transparency",
                            "source": "crt.sh",
                            "data": {
                                "domain": domain,
                                "certificate_count": len(certs),
                                "unique_names": len(seen_names),
                                "subdomains": subdomains[:100],
                            },
                            "confidence": 0.95,
                            "relevance_score": 0.85,
                            "tags": ["dns", "certificates", "transparency", "subdomains"],
                        })
        except Exception as e:
            logger.debug(f"crt.sh query failed for {domain}: {e}")

        return results

    async def _reverse_dns(self, domain: str) -> List[Dict]:
        """Resolve domain to IPs then reverse-lookup for co-hosted domains."""
        results = []
        ips = self._query_record(domain, "A")

        for ip in ips[:5]:
            try:
                loop = asyncio.get_event_loop()
                ptr = await loop.run_in_executor(None, self._ptr_lookup, ip)
                if ptr:
                    results.append({
                        "type": "reverse_dns",
                        "source": "dns_recon",
                        "data": {"ip": ip, "ptr_record": ptr, "original_domain": domain},
                        "confidence": 1.0,
                        "relevance_score": 0.7,
                        "tags": ["dns", "reverse", "ptr"],
                    })
            except Exception:
                pass

        return results

    def _ptr_lookup(self, ip: str) -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    async def _check_dnssec(self, domain: str) -> List[Dict]:
        """Check DNSSEC configuration."""
        try:
            loop = asyncio.get_event_loop()
            dnskey = await loop.run_in_executor(None, self._query_record, domain, "DNSKEY")
            ds = await loop.run_in_executor(None, self._query_record, domain, "DS")

            return [{
                "type": "dnssec",
                "source": "dns_recon",
                "data": {
                    "domain": domain,
                    "dnssec_enabled": bool(dnskey or ds),
                    "dnskey_count": len(dnskey),
                    "ds_records": ds,
                },
                "confidence": 1.0,
                "relevance_score": 0.6,
                "tags": ["dns", "dnssec", "security"],
            }]
        except Exception:
            return []

    # ── classic enumeration (Phrack / textfiles) ────────────────────────────

    def _authoritative_ns_ips(self, domain: str) -> List[str]:
        """Resolve the domain's authoritative nameservers to IPs."""
        ips: List[str] = []
        for ns in self._query_record(domain, "NS"):
            ips += self._query_record(str(ns).rstrip("."), "A")
        return ips

    async def _nsec_walk(self, domain: str) -> List[Dict]:
        """
        DNSSEC zone walking. NSEC-signed zones leak every name via the NSEC
        `next` chain even when AXFR is refused. NSEC3 hashes the names, so we
        detect it but don't attempt an (offline-cracking) walk.
        """
        loop = asyncio.get_event_loop()
        try:
            ns_ips = await loop.run_in_executor(None, self._authoritative_ns_ips, domain)
        except Exception:
            ns_ips = []
        if not ns_ips:
            return []

        try:
            walked, mode = await loop.run_in_executor(
                None, self._do_nsec_walk, domain, ns_ips[0])
        except Exception as e:
            logger.debug("NSEC walk failed for %s: %s", domain, e)
            return []

        if mode == "nsec3":
            return [{
                "type": "dnssec_nsec3",
                "source": "dns_recon",
                "data": {"domain": domain,
                         "note": "Zone uses NSEC3 (hashed) — names not directly enumerable"},
                "confidence": 1.0, "relevance_score": 0.5,
                "tags": ["dns", "dnssec", "nsec3"],
            }]
        if not walked:
            return []
        results = [{
            "type": "nsec_zone_walk",
            "source": "dns_recon",
            "data": {"domain": domain, "names_found": len(walked),
                     "names": sorted(walked)[:200]},
            "confidence": 1.0, "relevance_score": 0.9,
            "tags": ["dns", "dnssec", "nsec", "zone-walk"], "is_anomaly": True,
        }]
        # Emit in-zone names as subdomains so they feed the pivot + takeover.
        for name in sorted(walked):
            if name != domain and name.endswith("." + domain):
                results.append({
                    "type": "subdomain", "source": "dns_recon",
                    "data": {"subdomain": name, "domain": domain, "origin": "nsec"},
                    "confidence": 1.0, "relevance_score": 0.75,
                    "tags": ["dns", "subdomain", "nsec"],
                })
        return results

    def _do_nsec_walk(self, domain: str, ns_ip: str):
        """Blocking NSEC walk against one authoritative NS. Returns (names, mode)."""
        # First response decides the mode: NSEC (walkable) vs NSEC3 (hashed).
        first = self._nsec_query(domain, ns_ip)
        if first is not None and self._has_nsec3(first):
            return set(), "nsec3"

        def next_of(name: str):
            resp = self._nsec_query(name, ns_ip)
            nsec = self._extract_nsec(resp) if resp is not None else None
            return nsec[1] if nsec else None

        return nsec_walk_names(next_of, domain), "nsec"

    def _nsec_query(self, name: str, ns_ip: str):
        """Send a non-recursive DNSSEC query and return the response (or None)."""
        try:
            q = dns.message.make_query(name, dns.rdatatype.NSEC, want_dnssec=True)
            q.flags &= ~dns.flags.RD
            return dns.query.udp(q, ns_ip, timeout=4)
        except Exception:
            return None

    @staticmethod
    def _extract_nsec(resp):
        for rrset in list(resp.answer) + list(resp.authority):
            if rrset.rdtype == dns.rdatatype.NSEC:
                owner = str(rrset.name).rstrip(".")
                nxt = str(rrset[0].next).rstrip(".")
                return owner, nxt
        return None

    @staticmethod
    def _has_nsec3(resp) -> bool:
        for rrset in list(resp.answer) + list(resp.authority):
            if rrset.rdtype in (dns.rdatatype.NSEC3, dns.rdatatype.NSEC3PARAM):
                return True
        return False

    async def _ptr_sweep(self, domain: str) -> List[Dict]:
        """Sweep the /24 around the domain's A record for co-hosted PTR names."""
        loop = asyncio.get_event_loop()
        a_records = await loop.run_in_executor(None, self._query_record, domain, "A")
        if not a_records:
            return []
        ip = a_records[0]
        targets = hosts_in_24(ip)
        sem = asyncio.Semaphore(100)

        async def one(addr):
            async with sem:
                ptr = await loop.run_in_executor(None, self._ptr_lookup, addr)
                return addr, ptr

        pairs = await asyncio.gather(*(one(a) for a in targets), return_exceptions=True)
        hosts = [(a, p) for r in pairs if isinstance(r, tuple) for a, p in [r] if p]

        if not hosts:
            return []
        results = [{
            "type": "ptr_sweep_summary",
            "source": "dns_recon",
            "data": {"domain": domain, "netblock": f"{ip}/24",
                     "resolved": len(hosts),
                     "hosts": [{"ip": a, "ptr": p} for a, p in hosts[:120]]},
            "confidence": 1.0, "relevance_score": 0.75,
            "tags": ["dns", "reverse", "ptr", "netblock"],
        }]
        # Co-hosted names within the target's registered domain feed the pivot.
        for a, p in hosts:
            name = p.rstrip(".").lower()
            if name.endswith("." + domain) or name == domain:
                results.append({
                    "type": "subdomain", "source": "dns_recon",
                    "data": {"subdomain": name, "domain": domain, "origin": "ptr"},
                    "confidence": 0.8, "relevance_score": 0.6,
                    "tags": ["dns", "subdomain", "ptr"],
                })
        return results

    async def _cache_snoop(self, domain: str) -> List[Dict]:
        """
        Non-recursive (RD=0) probes of the domain's nameservers. An NS that
        answers recursive queries for third-party domains is an open resolver;
        the cached answers reveal what its users recently looked up.
        """
        loop = asyncio.get_event_loop()
        ns_ips = await loop.run_in_executor(None, self._authoritative_ns_ips, domain)
        if not ns_ips:
            return []
        ns_ip = ns_ips[0]

        def probe(name: str) -> bool:
            try:
                q = dns.message.make_query(name, dns.rdatatype.A)
                q.flags &= ~dns.flags.RD                      # non-recursive
                resp = dns.query.udp(q, ns_ip, timeout=3)
                return bool(resp.answer)                      # answered from cache
            except Exception:
                return False

        cached = []
        for probe_domain in CACHE_SNOOP_PROBES:
            if await loop.run_in_executor(None, probe, probe_domain):
                cached.append(probe_domain)

        if not cached:
            return []
        return [{
            "type": "dns_cache_snoop",
            "source": "dns_recon",
            "data": {"domain": domain, "nameserver": ns_ip,
                     "cached_domains": cached,
                     "detail": "Nameserver answers non-recursive queries for third-party "
                               "domains — open resolver, cache-snoopable"},
            "confidence": 0.85, "relevance_score": 0.85,
            "tags": ["dns", "cache-snoop", "open-resolver", "misconfig"],
            "is_anomaly": True,
        }]

    async def _check_spf_dmarc(self, domain: str) -> List[Dict]:
        """Check email security: SPF, DMARC, DKIM selectors."""
        results = []

        txt_records = self._query_record(domain, "TXT")
        spf = [r for r in txt_records if "v=spf1" in r.lower()]
        dmarc_records = self._query_record(f"_dmarc.{domain}", "TXT")
        dmarc = [r for r in dmarc_records if "v=dmarc1" in r.lower()]

        email_security = {
            "domain": domain,
            "spf_configured": bool(spf),
            "spf_record": spf[0] if spf else None,
            "dmarc_configured": bool(dmarc),
            "dmarc_record": dmarc[0] if dmarc else None,
            "email_security_score": (50 if spf else 0) + (50 if dmarc else 0),
            "spoofable": not spf or not dmarc,
        }

        results.append({
            "type": "email_security",
            "source": "dns_recon",
            "data": email_security,
            "confidence": 1.0,
            "relevance_score": 0.8,
            "tags": ["dns", "email", "spf", "dmarc", "security"],
            "is_anomaly": email_security["spoofable"],
        })

        return results

    def _extract_domain(self, target: str) -> Optional[str]:
        if not target:
            return None
        if target.startswith("http"):
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        return target.split("/")[0].split(":")[0]
