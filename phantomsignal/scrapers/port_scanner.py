"""
PhantomSignal Port Scanner — Ghost Probe Network Recon
Probe chain: nmap (version + OS detection) → pure-Python async TCP fallback.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
import socket
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

logger = logging.getLogger("phantomsignal.port_scanner")

# Expanded common port list — low privileged + high-numbered services
COMMON_PORTS = [
    # Low / privileged
    21, 22, 23, 25, 53, 69, 79, 80, 88, 110, 111, 113, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445,
    465, 512, 513, 514, 515, 587, 631, 636, 993, 995,
    # VPN / tunnels
    1080, 1194, 1723,
    # Databases
    1433, 1521, 1883, 3306, 5432, 5984, 6379, 7474,
    9200, 9300, 11211, 27017, 27018, 28017,
    # DevOps / cloud / big-data
    2049, 2181, 2375, 2376, 4848, 5601, 5672,
    6443, 7001, 7443, 8983, 9418, 15672, 50070, 50030,
    # Web / proxy / alternate HTTP
    3000, 3128, 4000, 4200, 4443, 5000,
    8000, 8008, 8080, 8081, 8082, 8086, 8088, 8443,
    8888, 8889, 9000, 9001, 9090, 9091, 10000,
    # Windows-specific
    3389, 5985, 5986, 49152,
    # Other notable
    4444, 4899, 5900, 6000, 7000, 7070,
]

TOP_1000_PORTS = sorted(set(list(range(1, 1025)) + [
    1080, 1194, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376,
    3000, 3128, 3306, 3389, 4000, 4444, 4848, 5000, 5432, 5601,
    5672, 5900, 5984, 5985, 5986, 6379, 6443, 7001, 7443, 7474,
    8000, 8008, 8080, 8081, 8082, 8086, 8088, 8443, 8888, 8889,
    9000, 9001, 9090, 9091, 9200, 9300, 9418, 10000, 11211, 15672,
    27017, 27018, 28017, 50070, 50030,
]))

SERVICE_NAMES: Dict[int, str] = {
    20: "FTP-DATA",   21: "FTP",          22: "SSH",        23: "TELNET",
    25: "SMTP",       53: "DNS",          67: "DHCP",       68: "DHCP",
    69: "TFTP",       79: "FINGER",       80: "HTTP",       88: "KERBEROS",
    110: "POP3",      111: "RPCBIND",     113: "IDENT",     119: "NNTP",
    123: "NTP",       135: "MSRPC",       137: "NETBIOS-NS",
    138: "NETBIOS-DGM", 139: "NETBIOS-SSN", 143: "IMAP",
    161: "SNMP",      162: "SNMP-TRAP",   179: "BGP",       194: "IRC",
    389: "LDAP",      443: "HTTPS",       445: "SMB",       465: "SMTPS",
    512: "REXEC",     513: "RLOGIN",      514: "SYSLOG",    515: "LPD",
    587: "SMTP-SUB",  631: "IPP",         636: "LDAPS",     993: "IMAPS",
    995: "POP3S",     1080: "SOCKS",      1194: "OPENVPN",  1433: "MSSQL",
    1521: "ORACLE",   1723: "PPTP",       1883: "MQTT",     2049: "NFS",
    2181: "ZOOKEEPER", 2375: "DOCKER-API", 2376: "DOCKER-TLS",
    3000: "HTTP-ALT", 3128: "PROXY",      3306: "MYSQL",    3389: "RDP",
    4000: "HTTP-ALT", 4444: "METASPLOIT", 4848: "GLASSFISH",
    4899: "RADMIN",   5000: "HTTP-ALT",   5432: "POSTGRESQL",
    5601: "KIBANA",   5672: "AMQP",       5900: "VNC",      5984: "COUCHDB",
    5985: "WINRM",    5986: "WINRM-TLS",  6379: "REDIS",    6443: "KUBERNETES",
    7001: "WEBLOGIC", 7474: "NEO4J",      8008: "HTTP-ALT", 8080: "HTTP-PROXY",
    8082: "HTTP-ALT", 8083: "HTTP-ALT",   8086: "INFLUXDB", 8088: "HTTP-ALT",
    8443: "HTTPS-ALT", 8888: "HTTP-ALT",  8889: "HTTP-ALT", 8983: "SOLR",
    9000: "HTTP-ALT", 9001: "HTTP-ALT",   9090: "PROMETHEUS",
    9200: "ELASTICSEARCH", 9300: "ES-CLUSTER",
    9418: "GIT",      10000: "WEBMIN",    11211: "MEMCACHED",
    15672: "RABBITMQ-MGMT", 27017: "MONGODB", 27018: "MONGODB",
    28017: "MONGODB-WEB", 49152: "MSRPC-DYN", 50070: "HADOOP-NN",
}

BANNER_PROBES: Dict[int, bytes] = {
    21:    b"",
    22:    b"",
    23:    b"\r\n",
    25:    b"EHLO phantomsignal.local\r\n",
    79:    b"root\r\n",
    80:    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    110:   b"",
    143:   b"",
    443:   b"",
    465:   b"",
    587:   b"EHLO phantomsignal.local\r\n",
    993:   b"",
    995:   b"",
    1433:  b"",
    3306:  b"",
    5432:  b"",
    5900:  b"",
    5984:  b"GET / HTTP/1.0\r\n\r\n",
    6379:  b"PING\r\n",
    7474:  b"GET / HTTP/1.0\r\n\r\n",
    8080:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    9000:  b"GET / HTTP/1.0\r\n\r\n",
    9090:  b"GET / HTTP/1.0\r\n\r\n",
    9200:  b"GET / HTTP/1.0\r\n\r\n",
    10000: b"GET / HTTP/1.0\r\n\r\n",
    11211: b"stats\r\n",
    15672: b"GET / HTTP/1.0\r\n\r\n",
    27017: (
        b"\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00"
        b"\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff"
        b"\x13\x00\x00\x00\x10serverStatus\x00\x01\x00\x00\x00\x00"
    ),
}

DANGEROUS_PORTS: Dict[int, str] = {
    21:    "FTP — anonymous login risk",
    23:    "TELNET — unencrypted remote access",
    79:    "FINGER — user enumeration",
    111:   "RPCBIND — RPC portmapper exposure",
    135:   "MSRPC — Windows attack surface",
    139:   "NETBIOS — SMB/Windows sharing",
    445:   "SMB — critical Windows attack vector",
    512:   "REXEC — unencrypted remote execution",
    513:   "RLOGIN — unencrypted remote login",
    1433:  "MSSQL — database exposure",
    1521:  "Oracle DB — database exposure",
    2375:  "Docker API — CRITICAL: container escape",
    3306:  "MySQL — database exposure",
    3389:  "RDP — remote desktop exposure",
    4444:  "Metasploit default — possible backdoor",
    4899:  "Radmin — remote admin tool",
    5432:  "PostgreSQL — database exposure",
    5900:  "VNC — remote desktop exposure",
    5985:  "WinRM HTTP — remote management",
    5986:  "WinRM HTTPS — remote management",
    6379:  "Redis — often unauthenticated",
    9200:  "Elasticsearch — often unauthenticated",
    10000: "Webmin — admin interface exposure",
    11211: "Memcached — DDoS amplification risk",
    27017: "MongoDB — often unauthenticated",
    50070: "Hadoop NameNode — big data exposure",
}


class PortScanner:
    """Port scanner: nmap (version + OS detection) with async-TCP fallback."""

    def __init__(self, config):
        self.config          = config
        self.timeout         = config.get("port_scanner", "timeout",         default=3)
        self.max_concurrent  = config.get("port_scanner", "max_concurrent",  default=300)
        self.service_detection = config.get("port_scanner", "service_detection", default=True)
        self._nmap           = shutil.which("nmap")

    # ── Public ──────────────────────────────────────────────────────────────

    async def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scan_profile: str = "common",
    ) -> List[Dict]:
        """Ghost probe a target. Tries nmap first, falls back to async TCP."""
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

        logger.info(f"Scanning {host} — {len(ports)} ports, profile={scan_profile}, nmap={'yes' if self._nmap else 'no'}")

        open_ports:  List[Dict] = []
        os_info:     Optional[Dict] = None
        scan_engine: str = "python"

        if self._nmap:
            nmap_result = await self._try_nmap(host, ports)
            if nmap_result is not None:
                open_ports  = nmap_result["ports"]
                os_info     = nmap_result.get("os")
                scan_engine = "nmap"
                logger.info(f"nmap: {len(open_ports)} open ports found")

        if not open_ports and scan_engine == "python":
            semaphore = asyncio.Semaphore(self.max_concurrent)
            tasks     = [self._probe_port(host, p, semaphore) for p in ports]
            raw       = await asyncio.gather(*tasks, return_exceptions=True)
            open_ports = [r for r in raw if isinstance(r, dict) and r.get("state") == "open"]

        results: List[Dict] = []
        for port_info in open_ports:
            port_info["scan_engine"] = scan_engine
            is_dangerous = port_info["port"] in DANGEROUS_PORTS
            results.append({
                "type":           "open_port",
                "source":         "port_scanner",
                "data":           port_info,
                "confidence":     1.0,
                "relevance_score": 0.9 if is_dangerous else 0.6,
                "tags":           ["port", "network"] + (["dangerous", "high_risk"] if is_dangerous else []),
                "is_anomaly":     is_dangerous,
            })

        if os_info:
            results.append({
                "type":           "os_detection",
                "source":         "port_scanner",
                "data": {
                    "target":    host,
                    "os_name":   os_info.get("name"),
                    "os_family": os_info.get("osfamily"),
                    "os_gen":    os_info.get("osgen"),
                    "accuracy":  os_info.get("accuracy", 0),
                    "cpe":       os_info.get("cpe"),
                },
                "confidence":     (os_info.get("accuracy", 0) / 100),
                "relevance_score": 0.9,
                "tags":           ["os", "fingerprint", "nmap"],
            })

        if open_ports:
            results.append({
                "type":   "port_scan_summary",
                "source": "port_scanner",
                "data": {
                    "target":        target,
                    "host":          host,
                    "total_scanned": len(ports),
                    "open_count":    len(open_ports),
                    "scan_engine":   scan_engine,
                    "open_ports":    sorted(p["port"] for p in open_ports),
                    "dangerous_ports": [
                        {"port": p["port"], "warning": DANGEROUS_PORTS[p["port"]]}
                        for p in open_ports if p["port"] in DANGEROUS_PORTS
                    ],
                    "risk_assessment": self._assess_risk(open_ports),
                },
                "confidence":     1.0,
                "relevance_score": 1.0,
                "tags":           ["summary", "port_scan"],
            })

        return results

    # ── nmap ────────────────────────────────────────────────────────────────

    async def _try_nmap(self, host: str, ports: List[int]) -> Optional[Dict]:
        """Run nmap -sV -O for rich version/OS data. Returns None on failure."""
        port_str = ",".join(str(p) for p in sorted(ports))
        cmd = [
            self._nmap,
            "-sV", "--version-intensity", "7",
            "-O", "--osscan-guess",
            "--open",
            "-p", port_str,
            "--host-timeout", "120s",
            "-oX", "-",
            host,
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
            xml_out = stdout.decode("utf-8", errors="replace")
            return self._parse_nmap_xml(xml_out) if xml_out.strip() else None
        except Exception as exc:
            logger.debug(f"nmap probe failed: {exc}")
            return None

    def _parse_nmap_xml(self, xml_str: str) -> Optional[Dict]:
        """Parse nmap XML output → {ports: [...], os: {...}}."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        ports:   List[Dict]     = []
        os_info: Optional[Dict] = None

        for host_elem in root.findall("host"):
            # OS detection — take the highest-accuracy match
            best_os    = None
            best_acc   = -1
            for osmatch in host_elem.findall(".//osmatch"):
                acc = int(osmatch.get("accuracy", 0))
                if acc > best_acc:
                    best_acc = acc
                    osclass  = osmatch.find("osclass")
                    cpe_elem = osclass.find("cpe") if osclass is not None else None
                    best_os  = {
                        "name":     osmatch.get("name"),
                        "accuracy": acc,
                        "osfamily": osclass.get("osfamily") if osclass is not None else None,
                        "osgen":    osclass.get("osgen")    if osclass is not None else None,
                        "cpe":      cpe_elem.text           if cpe_elem is not None else None,
                    }
            if best_os and os_info is None:
                os_info = best_os

            for port_elem in host_elem.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_num = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")
                svc_elem = port_elem.find("service")

                service_name = SERVICE_NAMES.get(port_num, "UNKNOWN")
                version      = ""
                banner       = ""

                if svc_elem is not None:
                    raw_svc   = svc_elem.get("name", "")
                    product   = svc_elem.get("product", "")
                    ver       = svc_elem.get("version", "")
                    extrainfo = svc_elem.get("extrainfo", "")
                    tunnel    = svc_elem.get("tunnel", "")
                    if raw_svc:
                        label        = f"{raw_svc}/{tunnel}" if tunnel else raw_svc
                        service_name = label.upper()
                    ver_parts = [p for p in [product, ver, extrainfo] if p]
                    version   = " ".join(ver_parts)[:60]

                # Banner from nmap script output
                for script in port_elem.findall("script"):
                    sid = script.get("id", "")
                    if any(k in sid for k in ("banner", "info", "identify", "version")):
                        banner = script.get("output", "")[:200].replace("\n", " ").strip()
                        break

                port_data: Dict = {
                    "port":          port_num,
                    "state":         "open",
                    "service":       service_name,
                    "banner":        banner,
                    "protocol":      protocol,
                    "danger_warning": DANGEROUS_PORTS.get(port_num),
                }
                if version:
                    port_data["version"] = version

                ports.append(port_data)

        return {"ports": ports, "os": os_info}

    # ── Pure-Python async TCP fallback ──────────────────────────────────────

    async def _probe_port(
        self, host: str, port: int, semaphore: asyncio.Semaphore
    ) -> Optional[Dict]:
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                banner  = ""
                service = SERVICE_NAMES.get(port, "UNKNOWN")

                if self.service_detection and port in BANNER_PROBES:
                    try:
                        probe = BANNER_PROBES[port]
                        if probe:
                            writer.write(probe)
                            await writer.drain()
                        data   = await asyncio.wait_for(reader.read(1024), timeout=2)
                        banner = data.decode("utf-8", errors="replace").strip()
                    except Exception:
                        pass

                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                port_data: Dict = {
                    "port":          port,
                    "state":         "open",
                    "service":       service,
                    "banner":        banner[:200] if banner else "",
                    "protocol":      "tcp",
                    "danger_warning": DANGEROUS_PORTS.get(port),
                }
                if banner:
                    ver = self._extract_version(banner, service)
                    if ver:
                        port_data["version"] = ver

                return port_data

            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception as exc:
                logger.debug(f"Port probe {host}:{port}: {exc}")
                return None

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _resolve_host(self, target: str) -> Optional[str]:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
            return target
        try:
            clean = target.replace("https://", "").replace("http://", "").split("/")[0]
            return socket.gethostbyname(clean)
        except Exception:
            return None

    def _extract_version(self, banner: str, service: str) -> Optional[str]:
        for pattern in (r"(\d+\.\d+[\.\d]*[-\w]*)", r"v(\d+\.\d+)", r"version\s+(\d+\.\d+)"):
            m = re.search(pattern, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def _assess_risk(self, open_ports: List[Dict]) -> Dict:
        dangerous  = [p for p in open_ports if p["port"] in DANGEROUS_PORTS]
        risk_score = min(len(dangerous) * 15 + len(open_ports) * 2, 100)
        level = (
            "CRITICAL" if risk_score >= 75 else
            "HIGH"     if risk_score >= 50 else
            "MEDIUM"   if risk_score >= 25 else
            "LOW"
        )
        return {
            "level":          level,
            "score":          risk_score,
            "dangerous_count": len(dangerous),
            "total_open":     len(open_ports),
            "summary":        (f"{len(dangerous)} high-risk service(s) exposed"
                               if dangerous else "No critical exposures detected"),
        }
