"""
PhantomSignal Infrastructure Pivot — Favicon Hash & TLS Certificate Fingerprinting

Phase 2 (final "modern recon sources" item). Fingerprints a target two ways and
pivots on each to surface sibling infrastructure:
  * favicon hash — the Shodan MurmurHash3 of the base64'd favicon; hosts serving
    the same favicon usually share an owner/stack. Pivoted via Shodan
    `http.favicon.hash:`.
  * TLS certificate — the leaf cert's SHA-256 fingerprint and Subject Alternative
    Names. Shared certs/SANs are a strong sibling-infra signal; the SANs reveal
    sibling hostnames directly (no external service needed) and feed the pivot.

Both discovered sibling IPs and cert SAN hostnames flow into the recursive pivot
engine and takeover detector.

NOTE on JARM: an active JARM/JA3S TLS-stack fingerprint was intended here, but a
correct implementation requires byte-exact reproduction of the Salesforce
10-probe algorithm; a from-scratch port produced malformed Client Hellos, and a
silently-wrong fingerprint is worse than none for a security tool. The TLS
certificate fingerprint below is the correct, verifiable TLS-pivot substitute;
JARM can be added later by vendoring the vetted reference with test vectors.

Design: MurmurHash3 and the Shodan favicon hash are pure and unit-tested (mmh3 is
reimplemented to avoid a native dependency). Network / socket I/O is in the class.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import socket
import ssl
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin

import httpx

logger = logging.getLogger("phantomsignal.scrapers.infra_pivot")

_LINK_ICON = re.compile(
    r"<link[^>]+rel\s*=\s*['\"][^'\"]*icon[^'\"]*['\"][^>]*>", re.IGNORECASE)
_HREF = re.compile(r"href\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
_HOST_RE = re.compile(r"^(?:(?!-)[a-z0-9_-]{1,63}(?<!-)\.)+[a-z]{2,63}$")


# ── MurmurHash3 x86_32 (matches the `mmh3` package; unit-tested) ─────────────

def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & 0xFFFFFFFC
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    val = length & 3
    if val == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if val >= 2:
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if val >= 1:
        k1 |= (data[rounded_end] & 0xFF)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def shodan_favicon_hash(favicon_bytes: bytes) -> int:
    """Shodan's favicon hash: MurmurHash3 of the base64-encoded icon (with the
    standard MIME line breaks that `base64.encodebytes` inserts)."""
    return murmur3_x86_32(base64.encodebytes(favicon_bytes))


def find_favicon_url(html: str, base_url: str) -> str:
    """Resolve the favicon URL from <link rel=icon>, else the /favicon.ico default."""
    for tag in _LINK_ICON.findall(html or ""):
        m = _HREF.search(tag)
        if m:
            return urljoin(base_url, m.group(1).strip())
    return urljoin(base_url, "/favicon.ico")


def cert_sha256(cert_der: bytes) -> str:
    """Colon-free lowercase SHA-256 fingerprint of a DER certificate."""
    return hashlib.sha256(cert_der).hexdigest()


def sans_from_cert(cert: dict, domain: str) -> Set[str]:
    """In-scope DNS SANs from a parsed peer certificate (getpeercert() dict)."""
    domain = domain.lower().rstrip(".")
    out: Set[str] = set()
    for typ, val in cert.get("subjectAltName", ()) or ():
        if typ.lower() != "dns":
            continue
        name = val.lower().lstrip("*.").rstrip(".")
        if _HOST_RE.match(name) and (name == domain or name.endswith(f".{domain}")):
            out.add(name)
    return out


# ── infra pivot ─────────────────────────────────────────────────────────────

class InfraPivot:
    def __init__(self, config):
        self.config = config
        self._shodan_key = config.get_api_key("shodan")

    async def run(self, target: str) -> List[Dict]:
        host = self._host(target)
        if not host:
            return []
        logger.info("Infra pivot (favicon + TLS cert) for %s", host)

        loop = asyncio.get_event_loop()
        favicon = await self._favicon_hash(host)
        cert_info = await loop.run_in_executor(None, self._tls_cert, host)

        results: List[Dict] = []

        if favicon is not None:
            results.append(self._fingerprint("favicon_hash", host, str(favicon),
                                              f"http.favicon.hash:{favicon}"))
            results += await self._shodan_pivot(f"http.favicon.hash:{favicon}", "favicon")

        if cert_info:
            fp = cert_info["sha256"]
            results.append(self._fingerprint("tls_cert_fingerprint", host, fp,
                                              f"ssl.cert.fingerprint:{fp}",
                                              extra={"subject_cn": cert_info.get("cn"),
                                                     "serial": cert_info.get("serial"),
                                                     "issuer": cert_info.get("issuer"),
                                                     "san_count": len(cert_info["sans"])}))
            # SAN hostnames are pivotable siblings — emit as subdomains for the graph.
            root = self._registered(host)
            for san in sorted(cert_info["sans"]):
                if san == host:
                    continue
                results.append({
                    "type": "subdomain",
                    "source": "infra_pivot",
                    "data": {"subdomain": san, "domain": root, "origin": "tls_san"},
                    "confidence": 0.7,
                    "relevance_score": 0.6,
                    "tags": ["infra", "subdomain", "tls-san"],
                })
            results += await self._shodan_pivot(f"ssl.cert.serial:{cert_info['serial']}", "tls_cert") \
                if cert_info.get("serial") else []

        return results

    # ── favicon ──────────────────────────────────────────────────────────────
    async def _favicon_hash(self, host: str) -> Optional[int]:
        base = f"https://{host}"
        try:
            async with httpx.AsyncClient(
                timeout=10, follow_redirects=True,
                headers={"User-Agent": "PhantomSignal-OSINT/1.0"},
            ) as client:
                page = await client.get(base)
                r = await client.get(find_favicon_url(page.text, base))
                if r.status_code == 200 and r.content:
                    return shodan_favicon_hash(r.content)
        except Exception as e:
            logger.debug("favicon fetch failed for %s: %s", host, e)
        return None

    # ── TLS certificate (stdlib ssl) ──────────────────────────────────────────
    def _tls_cert(self, host: str, port: int = 443) -> Optional[Dict]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
                    parsed = ss.getpeercert()  # requires verify? works with CERT_NONE? -> may be {}
        except Exception as e:
            logger.debug("TLS cert fetch failed for %s: %s", host, e)
            return None

        # With CERT_NONE, getpeercert() returns {}; re-parse the DER for SAN/CN.
        info = {"sha256": cert_sha256(der), "sans": set(), "cn": None,
                "serial": None, "issuer": None}
        details = parsed or self._parse_der(der, host)
        info["sans"] = sans_from_cert(details, self._registered(host))
        subj = dict(x[0] for x in details.get("subject", ())) if details.get("subject") else {}
        issr = dict(x[0] for x in details.get("issuer", ())) if details.get("issuer") else {}
        info["cn"] = subj.get("commonName")
        info["issuer"] = issr.get("commonName") or issr.get("organizationName")
        info["serial"] = details.get("serialNumber")
        return info

    @staticmethod
    def _parse_der(der: bytes, host: str) -> dict:
        """Parse a DER cert into the getpeercert()-style dict via cryptography if
        available; otherwise return an empty dict (fingerprint still works)."""
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID, NameOID
            cert = x509.load_der_x509_certificate(der)
            out: dict = {}
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            icn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            out["subject"] = ((("commonName", cn[0].value),),) if cn else ()
            out["issuer"] = ((("commonName", icn[0].value),),) if icn else ()
            out["serialNumber"] = format(cert.serial_number, "x")
            try:
                san = cert.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                names = san.get_values_for_type(x509.DNSName)
                out["subjectAltName"] = tuple(("DNS", n) for n in names)
            except Exception:
                out["subjectAltName"] = ()
            return out
        except Exception:
            return {}

    # ── Shodan pivot ──────────────────────────────────────────────────────────
    async def _shodan_pivot(self, query: str, kind: str) -> List[Dict]:
        if not self._shodan_key:
            return []
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self._shodan_key, "query": query, "minify": "true"},
                )
                if r.status_code != 200:
                    logger.debug("shodan pivot %s: HTTP %s", kind, r.status_code)
                    return []
                matches = r.json().get("matches", [])
        except Exception as e:
            logger.debug("shodan pivot failed (%s): %s", kind, e)
            return []

        results, seen = [], set()
        for m in matches[:100]:
            ip = m.get("ip_str")
            if not ip or ip in seen:
                continue
            seen.add(ip)
            results.append({
                "type": "infra_sibling",
                "source": "infra_pivot",
                "data": {"ip": ip, "pivot_kind": kind,
                         "hostnames": m.get("hostnames", []),
                         "port": m.get("port"), "org": m.get("org")},
                "confidence": 0.75,
                "relevance_score": 0.7,
                "tags": ["infra", "pivot", kind, "sibling"],
            })
        return results

    def _fingerprint(self, ftype: str, host: str, value: str, dork: str,
                     extra: Optional[Dict] = None) -> Dict:
        return {
            "type": ftype,
            "source": "infra_pivot",
            "data": {"host": host, "value": value, "shodan_dork": dork, **(extra or {})},
            "confidence": 0.95,
            "relevance_score": 0.7,
            "tags": ["infra", "fingerprint", ftype.split("_")[0]],
        }

    def _host(self, target: str) -> Optional[str]:
        t = (target or "").strip().lower()
        t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
        return t or None

    @staticmethod
    def _registered(host: str) -> str:
        try:
            import tldextract
            ext = tldextract.extract(host)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}".lower()
        except Exception:
            pass
        parts = host.lower().split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()
