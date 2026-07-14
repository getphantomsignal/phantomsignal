"""
PhantomSignal :: Shodan Integration — Internet-Wide Device Scanner

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

from typing import Dict, List

from phantomsignal.intel.apis.base import (
    APICategory, APITier, BaseIntelAPI, register_api
)


@register_api
class ShodanAPI(BaseIntelAPI):
    NAME = "shodan"
    DESCRIPTION = "Search engine for internet-connected devices — ports, banners, vulns"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.NETWORK, APICategory.VULNERABILITY]
    RATE_LIMIT_PER_MINUTE = 60
    BASE_URL = "https://api.shodan.io"
    DOCS_URL = "https://developer.shodan.io/api"
    SIGN_UP_URL = "https://account.shodan.io/register"

    async def search(self, query: str, **kwargs) -> List[Dict]:
        if not self.is_configured:
            return []

        results = []
        import re
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", query))

        if is_ip:
            results.extend(await self._host_lookup(query))
        else:
            results.extend(await self._search_query(query))
        return results

    async def _host_lookup(self, ip: str) -> List[Dict]:
        data = await self._get(
            f"{self.BASE_URL}/shodan/host/{ip}",
            params={"key": self._api_key},
        )
        if "error" in data:
            return []

        ports = data.get("ports", [])
        vulns = data.get("vulns", {})
        services = []

        for item in data.get("data", []):
            services.append({
                "port": item.get("port"),
                "protocol": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:500],
                "module": item.get("_shodan", {}).get("module", ""),
                "hostname": item.get("hostnames", []),
                "timestamp": item.get("timestamp"),
                "cpe": item.get("cpe", []),
                "tags": item.get("tags", []),
            })

        results = [self._wrap_result(
            "shodan_host",
            {
                "ip": ip,
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "os": data.get("os"),
                "ports": ports,
                "open_port_count": len(ports),
                "services": services,
                "vulnerabilities": list(vulns.keys()) if vulns else [],
                "vuln_count": len(vulns),
                "last_update": data.get("last_update"),
                "tags": data.get("tags", []),
            },
            confidence=1.0,
            relevance_score=0.95,
            tags=["shodan", "host", "network"] + (["vulnerabilities"] if vulns else []),
            is_anomaly=bool(vulns),
        )]

        if vulns:
            for cve, vuln_data in list(vulns.items())[:20]:
                results.append(self._wrap_result(
                    "vulnerability",
                    {
                        "cve": cve,
                        "ip": ip,
                        "cvss": vuln_data.get("cvss"),
                        "summary": vuln_data.get("summary", ""),
                        "references": vuln_data.get("references", [])[:3],
                    },
                    confidence=0.9,
                    relevance_score=1.0,
                    tags=["shodan", "vulnerability", "cve"],
                    is_anomaly=True,
                ))

        return results

    async def _search_query(self, query: str) -> List[Dict]:
        data = await self._get(
            f"{self.BASE_URL}/shodan/host/search",
            params={"key": self._api_key, "query": query, "minify": "false"},
        )
        if "error" in data or "matches" not in data:
            return []

        results = [self._wrap_result(
            "shodan_search",
            {
                "query": query,
                "total": data.get("total", 0),
                "matches": [
                    {
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "org": m.get("org"),
                        "country": m.get("location", {}).get("country_name"),
                        "product": m.get("product", ""),
                        "version": m.get("version", ""),
                        "banner": m.get("data", "")[:200],
                        "vulns": list(m.get("vulns", {}).keys()),
                    }
                    for m in data.get("matches", [])[:50]
                ],
            },
            confidence=0.95,
            relevance_score=0.85,
            tags=["shodan", "search", "network"],
        )]
        return results

    async def geo_search(self, query: str, *, limit: int = 100) -> Dict:
        """Geo/asset search that KEEPS per-match location (lat/lon/city) so Geo
        Recon can map results. Returns {total, matches, configured, error?}."""
        if not self.is_configured:
            return {"total": 0, "matches": [], "configured": False}
        try:
            data = await self._get(
                f"{self.BASE_URL}/shodan/host/search",
                params={"key": self._api_key, "query": query, "minify": "false"},
            )
        except Exception as e:
            # Key present but rejected/errored — configured, but unusable.
            return {"total": 0, "matches": [], "configured": True, "error": str(e)}
        if "error" in data or "matches" not in data:
            return {"total": 0, "matches": [], "configured": True, "error": data.get("error")}
        matches = []
        for m in data.get("matches", [])[:limit]:
            loc = m.get("location", {}) or {}
            matches.append({
                "ip": m.get("ip_str"), "port": m.get("port"),
                "transport": m.get("transport", "tcp"),
                "org": m.get("org"), "isp": m.get("isp"),
                "product": m.get("product", ""), "version": m.get("version", ""),
                "hostnames": m.get("hostnames", []),
                "country": loc.get("country_name"), "city": loc.get("city"),
                "lat": loc.get("latitude"), "lon": loc.get("longitude"),
                "vulns": list(m.get("vulns", {}).keys()),
                "banner": (m.get("data", "") or "")[:200],
            })
        return {"total": data.get("total", 0), "matches": matches, "configured": True}

    async def dns_resolve(self, hostnames: List[str]) -> Dict:
        data = await self._get(
            f"{self.BASE_URL}/dns/resolve",
            params={"key": self._api_key, "hostnames": ",".join(hostnames)},
        )
        return data

    async def reverse_dns(self, ips: List[str]) -> Dict:
        data = await self._get(
            f"{self.BASE_URL}/dns/reverse",
            params={"key": self._api_key, "ips": ",".join(ips)},
        )
        return data

    async def get_api_info(self) -> Dict:
        return await self._get(
            f"{self.BASE_URL}/api-info",
            params={"key": self._api_key},
        )
