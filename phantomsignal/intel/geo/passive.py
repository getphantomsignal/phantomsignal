"""
Free / passive Geo Recon primitives — a no-key alternative to Shodan's paid
search index (spec §1 asset side).

Shodan's geo search is a paid, pre-built index. For users without it we rebuild
the capability from free, keyless primitives, given a *scope* (a domain or ASN)
rather than a blank map:

- **Shodan InternetDB** (``internetdb.shodan.io/{ip}``) — free, keyless, passive:
  ports / CPEs / hostnames / vulns per IP (Shodan's existing data, no scanning).
- **RIPEstat announced-prefixes** — free: ASN → its IP prefixes.
- **ip-api.com batch** — free reverse geoIP: IP → city / region / country / lat,lon.

All HTTP routes through the stealth client (spec §11). Pure parsing/sampling is
split out and unit-tested; the network orchestration lives in ``passive_recon``.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from typing import Dict, List, Optional

logger = logging.getLogger("phantomsignal.geo.passive")

INTERNETDB = "https://internetdb.shodan.io/{ip}"
RIPESTAT = "https://stat.ripe.net/data/announced-prefixes/data.json"
IPAPI_BATCH = "http://ip-api.com/batch"

_ASN_RE = re.compile(r"^\s*(?:AS)?(\d{1,10})\s*$", re.I)
# A small, safe subdomain set to widen a domain seed without a full brute force.
_SUBDOMAINS = ["", "www", "mail", "api", "dev", "vpn", "portal", "app", "cdn", "remote"]
_MAX_IPS = 60           # bound InternetDB/geoIP calls per run


def parse_asn(value: Optional[str]) -> Optional[int]:
    m = _ASN_RE.match(value or "")
    return int(m.group(1)) if m else None


def cpe_product(cpes: Optional[List[str]]) -> str:
    """cpe:/a:nginx:nginx:1.2 → 'nginx'."""
    for c in cpes or []:
        parts = str(c).split(":")
        if len(parts) >= 4 and parts[3]:
            return parts[3]
    return ""


def sample_ips_from_prefixes(prefixes: List[str], cap: int = _MAX_IPS) -> List[str]:
    """One representative IPv4 host per prefix (the first usable address), capped
    — enough to characterise a block without enumerating it."""
    ips: List[str] = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        host = net.network_address if net.num_addresses <= 2 else next(net.hosts(), None)
        if host is not None:
            ips.append(str(host))
        if len(ips) >= cap:
            break
    return ips


def assets_from(ip: str, idb: Dict, geo: Optional[Dict]) -> List[Dict]:
    """Expand an InternetDB record (+ geoIP) into one asset row per (ip, port)."""
    geo = geo or {}
    product = cpe_product(idb.get("cpes"))
    vulns = list(idb.get("vulns") or [])
    hostnames = list(idb.get("hostnames") or [])
    rows = []
    for port in (idb.get("ports") or []):
        rows.append({
            "ip": ip, "port": port, "transport": "tcp",
            "product": product, "version": "",
            "org": geo.get("org") or geo.get("as"), "isp": geo.get("isp"),
            "hostnames": hostnames,
            "country": geo.get("country"), "city": geo.get("city"),
            "lat": geo.get("lat"), "lon": geo.get("lon"),
            "vulns": vulns, "banner": "",
        })
    return rows


# ── network primitives (best-effort; each returns empty on failure) ──────────

async def asn_prefixes(client, asn: int) -> List[str]:
    try:
        r = await client.get(RIPESTAT, params={"resource": f"AS{asn}"})
        data = r.json()
        return [p["prefix"] for p in data.get("data", {}).get("prefixes", []) if p.get("prefix")]
    except Exception:
        return []


async def resolve_domain_ips(domain: str) -> List[str]:
    """Resolve a domain + a small subdomain set to A records (system resolver)."""
    loop = asyncio.get_event_loop()

    def _resolve(host):
        try:
            return list({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
        except Exception:
            return []

    hosts = [f"{s}.{domain}" if s else domain for s in _SUBDOMAINS]
    results = await asyncio.gather(*[loop.run_in_executor(None, _resolve, h) for h in hosts])
    ips: List[str] = []
    for res in results:
        for ip in res:
            if ip not in ips:
                ips.append(ip)
    return ips


async def internetdb(client, ip: str) -> Optional[Dict]:
    try:
        r = await client.get(INTERNETDB.format(ip=ip))
        data = r.json()
        return data if isinstance(data, dict) and data.get("ports") else None
    except Exception:
        return None


async def geoip_batch(client, ips: List[str]) -> Dict[str, Dict]:
    """ip-api.com batch (≤100/req) → {ip: {city, country, lat, lon, org, as}}."""
    out: Dict[str, Dict] = {}
    fields = "status,message,query,city,regionName,country,countryCode,lat,lon,org,isp,as"
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            r = await client.post(IPAPI_BATCH,
                                  json=[{"query": ip, "fields": fields} for ip in chunk])
            for rec in (r.json() or []):
                if rec.get("status") == "success" and rec.get("query"):
                    out[rec["query"]] = {
                        "city": rec.get("city"), "region": rec.get("regionName"),
                        "country": rec.get("country"), "cc": rec.get("countryCode"),
                        "lat": rec.get("lat"), "lon": rec.get("lon"),
                        "org": rec.get("org"), "isp": rec.get("isp"), "as": rec.get("as"),
                    }
        except Exception:
            continue
    return out


def place_matches(geo: Optional[Dict], city: Optional[str], country: Optional[str]) -> bool:
    """Loose geo filter: city substring, country by name or 2-letter code."""
    if not geo:
        return False
    if city and city.strip().lower() not in str(geo.get("city") or "").lower():
        return False
    if country:
        c = country.strip().lower()
        if c not in str(geo.get("country") or "").lower() and c != str(geo.get("cc") or "").lower():
            return False
    return True
