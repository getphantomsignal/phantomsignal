"""
PhantomSignal Port Scanner — Ghost Probe Network Recon
Probe chain: nmap (version + OS detection) → pure-Python async TCP fallback.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import re
import shutil
import socket
import time
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


# ── Passive OS fingerprinting (p0f-style, SYN-ACK TCP/IP signature) ──────────
#
# Everything below the class boundary here is pure and network-free: byte-level
# IP/TCP/option parsers and TTL→OS inference, unit-tested against crafted packets
# (raw capture needs CAP_NET_RAW, so the error-prone logic is validated offline).

# Standard initial TTLs. A packet's observed TTL is the initial value minus the
# hop count, so the origin's initial TTL is the smallest standard value that is
# >= the observed TTL (routers only ever decrement). The obsolete 32 initial
# (Win9x/ME) is deliberately excluded: an observed TTL of 32 today is far more
# likely a distant Unix/Linux host than a dead OS, so we don't mislabel it.
KNOWN_INITIAL_TTLS = (64, 128, 255)
MAX_PLAUSIBLE_HOPS = 32

# Initial TTL → OS family. Coarse but reliable at the family level; version-level
# claims from TTL alone would be false precision, so we don't make them.
TTL_OS_FAMILY: Dict[int, tuple] = {
    64:  ("Linux / macOS / BSD / Android",
          ["Linux", "macOS", "FreeBSD", "OpenBSD", "Android", "iOS"]),
    128: ("Windows", ["Windows"]),
    255: ("Network device / Solaris / AIX",
          ["Cisco IOS", "Solaris", "AIX", "router/firewall"]),
}


def snap_initial_ttl(observed_ttl: int):
    """
    Map an observed TTL to (initial_ttl, hop_count) using the smallest standard
    initial TTL that could have produced it. Returns (None, None) when no standard
    initial yields a plausible hop count (i.e. the packet isn't cleanly bucketable).
    """
    for initial in KNOWN_INITIAL_TTLS:
        if 0 < observed_ttl <= initial:
            hops = initial - observed_ttl
            if hops <= MAX_PLAUSIBLE_HOPS:
                return initial, hops
    return None, None


def parse_ip_header(pkt: bytes) -> Optional[Dict]:
    """Parse an IPv4 header from the front of a raw packet. None if malformed."""
    if len(pkt) < 20:
        return None
    ver_ihl = pkt[0]
    if (ver_ihl >> 4) != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl:
        return None
    return {
        "ihl":      ihl,
        "ttl":      pkt[8],
        "protocol": pkt[9],
        "src":      ".".join(str(b) for b in pkt[12:16]),
        "dst":      ".".join(str(b) for b in pkt[16:20]),
    }


def parse_tcp_header(seg: bytes) -> Optional[Dict]:
    """Parse a TCP header (options included if present). None if malformed."""
    if len(seg) < 20:
        return None
    data_offset = (seg[12] >> 4) * 4
    if data_offset < 20:
        return None
    # Options may be truncated by a short capture; slice tolerates that.
    options = seg[20:data_offset] if data_offset > 20 else b""
    return {
        "src_port":    int.from_bytes(seg[0:2], "big"),
        "dst_port":    int.from_bytes(seg[2:4], "big"),
        "data_offset": data_offset,
        "flags":       seg[13],
        "window":      int.from_bytes(seg[14:16], "big"),
        "options":     options,
    }


def parse_tcp_options(opts: bytes) -> Dict:
    """
    Parse TCP options into {order, mss, window_scale, sack_permitted, timestamps}.
    ``order`` is the sequence of option kinds — its shape is itself a fingerprint.
    Stops cleanly on EOL (0) or any malformed length rather than over-reading.
    """
    order: List[int] = []
    mss = None
    window_scale = None
    sack = False
    timestamps = False
    i, n = 0, len(opts)
    while i < n:
        kind = opts[i]
        if kind == 0:                      # End of Option List
            order.append(0)
            break
        if kind == 1:                      # NOP (no length byte)
            order.append(1)
            i += 1
            continue
        if i + 1 >= n:                     # length byte missing → truncated
            break
        length = opts[i + 1]
        if length < 2 or i + length > n:   # malformed / truncated option
            break
        order.append(kind)
        val = opts[i + 2:i + length]
        if kind == 2 and length == 4:
            mss = int.from_bytes(val, "big")
        elif kind == 3 and length == 3:
            window_scale = val[0]
        elif kind == 4 and length == 2:
            sack = True
        elif kind == 8 and length == 10:
            timestamps = True
        i += length
    return {
        "order": order, "mss": mss, "window_scale": window_scale,
        "sack_permitted": sack, "timestamps": timestamps,
    }


def fingerprint_os(sig: Dict) -> Optional[Dict]:
    """
    Infer OS family from a captured SYN-ACK signature. ``sig`` keys: observed_ttl
    (required), window, mss, window_scale, sack_permitted, timestamps,
    options_order. TTL→family is the confident signal; window / MSS / option shape
    are advisory evidence that can nudge confidence but never invent version-level
    precision. Returns None when the TTL isn't cleanly bucketable.
    """
    ttl = sig.get("observed_ttl")
    if not ttl:
        return None
    initial, hops = snap_initial_ttl(ttl)
    if initial is None:
        return None

    family, candidates = TTL_OS_FAMILY[initial]
    evidence = [f"initial TTL {initial} (observed {ttl}, ~{hops} hops)"]
    confidence = 0.65 if hops <= 20 else 0.5

    win = sig.get("window")
    if win:
        evidence.append(f"TCP window {win}")
    mss = sig.get("mss")
    if mss:
        evidence.append(f"MSS {mss}")
        if mss < 1460:
            evidence.append("MSS < 1460 → tunnelled/VPN path")
    if initial == 64 and sig.get("timestamps") and sig.get("sack_permitted"):
        evidence.append("TCP timestamps + SACK — typical of modern Linux/Unix")
        confidence = min(confidence + 0.10, 0.80)
    if initial == 128 and not sig.get("timestamps"):
        evidence.append("no TCP timestamps — typical of Windows defaults")
        confidence = min(confidence + 0.05, 0.80)

    return {
        "os_family":      family,
        "candidates":     candidates,
        "observed_ttl":   ttl,
        "initial_ttl":    initial,
        "hop_count":      hops,
        "tcp_window":     win,
        "mss":            mss,
        "window_scale":   sig.get("window_scale"),
        "sack_permitted": sig.get("sack_permitted"),
        "timestamps":     sig.get("timestamps"),
        "tcp_options":    sig.get("options_order"),
        "confidence":     round(confidence, 2),
        "evidence":       evidence,
    }


# ── Stealth scan profiles (idle / decoy) — nmap command construction ─────────
#
# Idle and decoy scans need raw packet crafting / source-IP spoofing, so they are
# nmap-only and require root/CAP_NET_RAW at runtime. The command construction is
# pure and unit-tested; the privileged execution degrades honestly (see scan()).

STEALTH_PROFILES = ("decoy", "idle")


def _validate_nmap_operand(value: str, what: str) -> str:
    """
    Reject operands that could be misread as nmap flags. argv is passed straight
    to exec (no shell), so the only injection risk is a value that begins with
    ``-`` and gets parsed as an option — guard against exactly that.
    """
    v = str(value).strip()
    if not v:
        raise ValueError(f"{what} is empty")
    for part in v.split(","):
        p = part.strip()
        if not p or p.startswith("-"):
            raise ValueError(f"invalid {what}: {part!r}")
    return v


def build_nmap_command(nmap_path: str, host: str, ports: List[int],
                       stealth: Optional[str] = None,
                       decoys: Optional[str] = None,
                       zombie: Optional[str] = None) -> List[str]:
    """
    Build the nmap argv for a scan profile. ``stealth`` is None (rich -sV/-O
    scan), "decoy" (SYN scan behind decoy source IPs), or "idle" (zombie-bounced
    side-channel scan). Idle/decoy deliberately omit -sV/-O: over the idle side
    channel there is no direct response to probe, and version/OS probes in a
    decoy scan would originate from the real IP and defeat the decoys. Both use
    -Pn to skip host discovery (which would also leak the real IP). Pure/testable.
    """
    port_str = ",".join(str(p) for p in sorted(ports))
    common = ["--open", "-p", port_str, "--host-timeout", "120s", "-oX", "-"]
    host = _validate_nmap_operand(host, "target host")

    if stealth is None:
        return [nmap_path, "-sV", "--version-intensity", "7",
                "-O", "--osscan-guess"] + common + [host]

    if stealth == "decoy":
        spec = _validate_nmap_operand(decoys or "RND:10", "decoy spec")
        return [nmap_path, "-sS", "-D", spec, "-Pn"] + common + [host]

    if stealth == "idle":
        if not zombie:
            raise ValueError("idle scan requires a zombie host")
        z = _validate_nmap_operand(zombie, "zombie host")
        return [nmap_path, "-sI", z, "-Pn"] + common + [host]

    raise ValueError(f"unknown stealth profile: {stealth!r}")


class PortScanner:
    """Port scanner: nmap (version + OS detection) with async-TCP fallback."""

    def __init__(self, config):
        self.config          = config
        self.timeout         = config.get("port_scanner", "timeout",         default=3)
        self.max_concurrent  = config.get("port_scanner", "max_concurrent",  default=300)
        self.service_detection = config.get("port_scanner", "service_detection", default=True)
        self.os_fingerprint  = config.get("port_scanner", "os_fingerprint",     default=True)
        self._nmap           = shutil.which("nmap")

    # ── Public ──────────────────────────────────────────────────────────────

    async def scan(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        scan_profile: str = "common",
        stealth: Optional[str] = None,
        decoys: Optional[str] = None,
        zombie: Optional[str] = None,
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

        # Stealth profiles (idle/decoy) take a separate, nmap-only path — we never
        # fall back to the plain Python connect scan for them, which would send
        # traffic from our real IP and defeat the requested stealth.
        if stealth:
            return await self._stealth_scan(target, host, ports, stealth, decoys, zombie)

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

        results: List[Dict] = self._open_port_findings(open_ports, scan_engine)

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

        # Passive OS fingerprint from the SYN-ACK — complements nmap and is the
        # only OS signal when nmap is absent. Silently skips without CAP_NET_RAW.
        if open_ports:
            passive = await self._passive_os_fingerprint(host, open_ports)
            if passive:
                results.append({
                    "type":           "passive_os",
                    "source":         "port_scanner",
                    "data":           {"target": host,
                                       "method": "passive SYN-ACK (p0f-style)",
                                       **passive},
                    "confidence":     passive["confidence"],
                    "relevance_score": 0.75,
                    "tags":           ["os", "fingerprint", "passive", "p0f"],
                })

        if open_ports:
            results.append(self._summary_finding(target, host, ports, open_ports, scan_engine))

        return results

    async def _stealth_scan(self, target: str, host: str, ports: List[int],
                            stealth: str, decoys: Optional[str],
                            zombie: Optional[str]) -> List[Dict]:
        """Run an nmap idle/decoy scan, or explain honestly why it can't run."""
        reason = None
        if stealth not in STEALTH_PROFILES:
            reason = f"unknown stealth profile {stealth!r}"
        elif not self._nmap:
            reason = "nmap is not installed"
        elif stealth == "idle" and not zombie:
            reason = "idle scan requires a zombie host (--zombie)"
        if reason:
            return [self._stealth_unavailable(target, host, stealth, reason)]

        logger.info(f"Stealth {stealth} scan of {host} — {len(ports)} ports")
        nmap_result = await self._try_nmap(host, ports, stealth=stealth,
                                           decoys=decoys, zombie=zombie)
        if nmap_result is None:
            return [self._stealth_unavailable(
                target, host, stealth,
                "nmap stealth scan could not run — it typically needs root/CAP_NET_RAW",
                detail=f"{stealth} scan crafts raw packets; grant nmap CAP_NET_RAW "
                       f"or run as root")]

        # Honesty guard: without raw-packet privileges nmap can silently downgrade
        # -sS to a plain connect scan (real IP, no decoys). Its XML records the
        # technique actually used, so a "connect" result means stealth wasn't
        # applied — report that rather than claiming a stealth scan happened.
        if nmap_result.get("scan_type") == "connect":
            return [self._stealth_unavailable(
                target, host, stealth,
                "nmap downgraded to a connect scan (no raw-packet privileges) — "
                "the scan ran from the real source IP and stealth was NOT applied")]

        open_ports = nmap_result["ports"]
        engine = f"nmap-{stealth}"
        # Idle/decoy yield port state only: no OS/version, and no passive SYN-ACK
        # capture (that would emit packets from our real IP, breaking stealth).
        results = self._open_port_findings(open_ports, engine)
        results.append(self._summary_finding(target, host, ports, open_ports, engine))
        return results

    # ── result assembly (shared by standard + stealth paths) ────────────────

    def _open_port_findings(self, open_ports: List[Dict], scan_engine: str) -> List[Dict]:
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
        return results

    def _summary_finding(self, target: str, host: str, ports: List[int],
                         open_ports: List[Dict], scan_engine: str) -> Dict:
        return {
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
        }

    def _stealth_unavailable(self, target: str, host: str, stealth: str,
                             reason: str, detail: Optional[str] = None) -> Dict:
        data = {
            "target":  target,
            "host":    host,
            "profile": stealth,
            "reason":  reason,
            "note":    "no scan was performed",
        }
        if detail:
            data["detail"] = detail
        return {
            "type":            "stealth_unavailable",
            "source":          "port_scanner",
            "data":            data,
            "confidence":      1.0,
            "relevance_score": 0.3,
            "tags":            ["port", "stealth", stealth, "unavailable"],
        }

    # ── nmap ────────────────────────────────────────────────────────────────

    async def _try_nmap(self, host: str, ports: List[int],
                        stealth: Optional[str] = None,
                        decoys: Optional[str] = None,
                        zombie: Optional[str] = None) -> Optional[Dict]:
        """Run nmap and parse its XML. Standard scan is -sV -O; stealth variants
        (idle/decoy) are built by build_nmap_command. Returns None on failure."""
        try:
            cmd = build_nmap_command(self._nmap, host, ports, stealth, decoys, zombie)
        except ValueError as exc:
            logger.error(f"nmap command build failed: {exc}")
            return None
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
        """Parse nmap XML output → {ports: [...], os: {...}, scan_type: str}."""
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return None

        # The actual scan technique nmap ran ("syn"/"connect"/"idle"/…). Lets the
        # stealth path detect a silent downgrade to a connect scan (which happens
        # when -sS is requested without raw-packet privileges).
        scaninfo  = root.find("scaninfo")
        scan_type = scaninfo.get("type") if scaninfo is not None else None

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

        return {"ports": ports, "os": os_info, "scan_type": scan_type}

    # ── Passive OS fingerprint (SYN-ACK capture) ────────────────────────────

    async def _passive_os_fingerprint(
        self, host: str, open_ports: List[Dict]
    ) -> Optional[Dict]:
        """Capture a SYN-ACK from one open port and infer the OS family from it."""
        if not self.os_fingerprint or not open_ports:
            return None
        port = min(p["port"] for p in open_ports)
        loop = asyncio.get_event_loop()
        try:
            sig = await loop.run_in_executor(None, self._capture_syn_ack, host, port)
        except Exception as exc:
            logger.debug(f"passive OS fingerprint failed: {exc}")
            return None
        return fingerprint_os(sig) if sig else None

    def _capture_syn_ack(self, host: str, port: int) -> Optional[Dict]:
        """
        Blocking: open a raw TCP socket, trigger a normal handshake to ``port``,
        and capture the target's SYN-ACK to read its TTL/window/options. Needs
        CAP_NET_RAW; returns None (no guess) when the raw socket is denied.
        """
        try:
            rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except (PermissionError, OSError) as exc:
            logger.debug(f"raw socket unavailable — skipping passive OS fingerprint ({exc})")
            return None

        rx.settimeout(self.timeout)
        tx = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tx.setblocking(False)
        try:
            try:
                tx.connect_ex((host, port))          # kick off the handshake
            except OSError:
                pass
            local_port = tx.getsockname()[1]
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                try:
                    pkt = rx.recv(65535)
                except (socket.timeout, OSError):
                    break
                ip = parse_ip_header(pkt)
                if not ip or ip["protocol"] != 6 or ip["src"] != host:
                    continue
                tcp = parse_tcp_header(pkt[ip["ihl"]:])
                if not tcp or tcp["dst_port"] != local_port:
                    continue
                if (tcp["flags"] & 0x12) != 0x12:    # require SYN+ACK
                    continue
                opts = parse_tcp_options(tcp["options"])
                return {
                    "observed_ttl":   ip["ttl"],
                    "window":         tcp["window"],
                    "mss":            opts["mss"],
                    "window_scale":   opts["window_scale"],
                    "sack_permitted": opts["sack_permitted"],
                    "timestamps":     opts["timestamps"],
                    "options_order":  opts["order"],
                }
            return None
        finally:
            for sock in (tx, rx):
                try:
                    sock.close()
                except Exception:
                    pass

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
