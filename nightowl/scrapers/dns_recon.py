"""
NightOwl DNS Recon — Mapping the Shadow Network
Full DNS enumeration: records, zone transfer, subdomain brute-force.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Dict, List, Optional
from urllib.parse import urlparse

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import httpx

logger = logging.getLogger("nightowl.dns_recon")

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
                    headers={"User-Agent": "NightOwl OSINT Framework"},
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
