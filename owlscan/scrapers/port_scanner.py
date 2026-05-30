"""
OwlScan Port Scanner — Ghost Probe Network Recon
Async TCP port scanner with service detection and banner grabbing.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import socket
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("owlscan.port_scanner")

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    587, 631, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883,
    2049, 2375, 2376, 3000, 3306, 3389, 4444, 4848, 5000, 5432,
    5601, 5672, 5900, 5984, 6379, 6443, 7001, 7443, 7474, 8000,
    8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418,
    11211, 15672, 27017, 27018, 28017, 50070,
]

TOP_1000_PORTS = list(range(1, 1025)) + [
    1025, 1194, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376,
    3000, 3128, 3306, 3389, 4444, 4848, 5000, 5432, 5601, 5672,
    5900, 5984, 6379, 6443, 7001, 7443, 7474, 8000, 8080, 8081,
    8443, 8888, 9000, 9090, 9200, 9300, 9418, 11211, 15672,
    27017, 27018, 28017, 50070, 50030,
]

SERVICE_NAMES: Dict[int, str] = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPCBIND", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NETBIOS-NS", 138: "NETBIOS-DGM",
    139: "NETBIOS-SSN", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP",
    179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "SYSLOG", 515: "LPD", 587: "SMTP-SUBMISSION",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1194: "OPENVPN", 1433: "MSSQL", 1521: "ORACLE",
    1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2181: "ZOOKEEPER",
    2375: "DOCKER-API", 2376: "DOCKER-TLS", 3000: "HTTP-ALT",
    3128: "PROXY", 3306: "MYSQL", 3389: "RDP", 4444: "METASPLOIT",
    4848: "GLASSFISH", 5000: "HTTP-ALT", 5432: "POSTGRESQL",
    5601: "KIBANA", 5672: "AMQP", 5900: "VNC", 5984: "COUCHDB",
    6379: "REDIS", 6443: "KUBERNETES", 7001: "WEBLOGIC",
    7474: "NEO4J", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
    8888: "HTTP-ALT", 9000: "HTTP-ALT", 9090: "PROMETHEUS",
    9200: "ELASTICSEARCH", 9300: "ELASTICSEARCH-CLUSTER",
    9418: "GIT", 11211: "MEMCACHED", 15672: "RABBITMQ-MGMT",
    27017: "MONGODB", 27018: "MONGODB", 28017: "MONGODB-WEB",
    50070: "HADOOP-NAMENODE",
}

BANNER_PROBES: Dict[int, bytes] = {
    21: b"",
    22: b"",
    25: b"EHLO owlscan\r\n",
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
    3306: b"",
    5432: b"",
    6379: b"PING\r\n",
    9200: b"GET / HTTP/1.0\r\n\r\n",
    27017: b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00",
}

DANGEROUS_PORTS = {
    21: "FTP — Often allows anonymous login",
    23: "TELNET — Unencrypted remote access",
    135: "MSRPC — Windows attack surface",
    139: "NETBIOS — SMB/Windows sharing",
    445: "SMB — Critical Windows attack vector",
    1433: "MSSQL — Database exposure",
    1521: "Oracle DB — Database exposure",
    2375: "Docker API — CRITICAL: Container escape risk",
    3306: "MySQL — Database exposure",
    3389: "RDP — Remote desktop exposure",
    4444: "Metasploit default — Possible backdoor",
    5432: "PostgreSQL — Database exposure",
    5900: "VNC — Remote desktop exposure",
    6379: "Redis — Often unauthenticated",
    9200: "Elasticsearch — Often unauthenticated",
    11211: "Memcached — Amplification DDoS risk",
    27017: "MongoDB — Often unauthenticated",
    50070: "Hadoop NameNode — Big data exposure",
}


class PortScanner:
    """Async stealth port scanner with service/banner detection."""

    def __init__(self, config):
        self.config = config
        self.timeout = config.get("port_scanner", "timeout", default=3)
        self.max_concurrent = config.get("port_scanner", "max_concurrent", default=300)
        self.service_detection = config.get("port_scanner", "service_detection", default=True)

    async def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scan_profile: str = "common",
    ) -> List[Dict]:
        """Ghost probe a target for open ports."""
        host = self._resolve_host(target)
        if not host:
            logger.error(f"Cannot resolve host: {target}")
            return []

        if ports is None:
            if scan_profile == "common":
                ports = COMMON_PORTS
            elif scan_profile == "top1000":
                ports = TOP_1000_PORTS
            elif scan_profile == "full":
                ports = list(range(1, 65536))
            else:
                ports = self.config.get("port_scanner", "default_ports", default=COMMON_PORTS)

        logger.info(f"Scanning {host} — {len(ports)} ports, profile: {scan_profile}")

        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._probe_port(host, port, semaphore) for port in ports]
        probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = [r for r in probe_results if isinstance(r, dict) and r.get("state") == "open"]

        results = []
        for port_info in open_ports:
            is_dangerous = port_info["port"] in DANGEROUS_PORTS
            results.append({
                "type": "open_port",
                "source": "port_scanner",
                "data": port_info,
                "confidence": 1.0,
                "relevance_score": 0.9 if is_dangerous else 0.6,
                "tags": ["port", "network"] + (["dangerous", "high_risk"] if is_dangerous else []),
                "is_anomaly": is_dangerous,
            })

        # Summary result
        if open_ports:
            results.append({
                "type": "port_scan_summary",
                "source": "port_scanner",
                "data": {
                    "target": target,
                    "host": host,
                    "total_scanned": len(ports),
                    "open_count": len(open_ports),
                    "open_ports": [p["port"] for p in open_ports],
                    "dangerous_ports": [
                        {"port": p["port"], "warning": DANGEROUS_PORTS[p["port"]]}
                        for p in open_ports if p["port"] in DANGEROUS_PORTS
                    ],
                    "risk_assessment": self._assess_risk(open_ports),
                },
                "confidence": 1.0,
                "relevance_score": 1.0,
                "tags": ["summary", "port_scan"],
            })

        return results

    async def _probe_port(
        self, host: str, port: int, semaphore: asyncio.Semaphore
    ) -> Optional[Dict]:
        async with semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

                banner = ""
                service = SERVICE_NAMES.get(port, "UNKNOWN")

                if self.service_detection and port in BANNER_PROBES:
                    try:
                        probe = BANNER_PROBES[port]
                        if probe:
                            writer.write(probe)
                            await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=2)
                        banner = data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                port_data = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner[:200] if banner else "",
                    "protocol": "tcp",
                    "danger_warning": DANGEROUS_PORTS.get(port),
                }

                # Version extraction from banner
                if banner:
                    version = self._extract_version(banner, service)
                    if version:
                        port_data["version"] = version

                return port_data

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as e:
                logger.debug(f"Port probe error {host}:{port}: {e}")
                return None

    def _resolve_host(self, target: str) -> Optional[str]:
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        try:
            clean = target.replace("https://", "").replace("http://", "").split("/")[0]
            return socket.gethostbyname(clean)
        except Exception:
            return None

    def _extract_version(self, banner: str, service: str) -> Optional[str]:
        patterns = [
            r"(\d+\.\d+[\.\d]*[-\w]*)",
            r"v(\d+\.\d+)",
            r"version\s+(\d+\.\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _assess_risk(self, open_ports: List[Dict]) -> Dict:
        dangerous = [p for p in open_ports if p["port"] in DANGEROUS_PORTS]
        risk_score = min(len(dangerous) * 15 + len(open_ports) * 2, 100)

        if risk_score >= 75:
            level = "CRITICAL"
        elif risk_score >= 50:
            level = "HIGH"
        elif risk_score >= 25:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "level": level,
            "score": risk_score,
            "dangerous_count": len(dangerous),
            "total_open": len(open_ports),
            "summary": f"{len(dangerous)} high-risk service(s) exposed" if dangerous else "No critical exposures detected",
        }


import re
