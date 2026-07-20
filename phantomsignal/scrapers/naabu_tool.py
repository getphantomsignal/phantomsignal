"""
PhantomSignal — naabu adapter (v1.26), a fast port-discovery speed path with the
native nmap/async port scanner as fallback.

naabu (ProjectDiscovery) sweeps ports far faster than the pure-Python scanner at
scale. Its fast path is raw-socket, so it is honestly tagged **attributable**
(like masscan and the native scanner) — port scanning reveals the operator's IP
regardless. Findings are normalised to the *same* ``open_port`` /
``port_scan_summary`` shape the native module emits, so scoring and the UI are
unchanged. Absent the binary, the native scanner runs instead.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List, Optional

from phantomsignal.scrapers._external import (
    ExternalTool, host_only, run_with_fallback,
)

logger = logging.getLogger("phantomsignal.scrapers.naabu")


def parse_naabu(stdout: str, target: str, opsec: str) -> List[Dict]:
    """naabu ``-json`` lines → native-compatible port findings."""
    from phantomsignal.scrapers.port_scanner import DANGEROUS_PORTS

    found: List[Dict] = []
    host: Optional[str] = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        port = obj.get("port")
        if not isinstance(port, int):
            continue
        host = obj.get("host") or obj.get("ip") or host
        found.append({
            "port": port,
            "ip": obj.get("ip"),
            "host": obj.get("host"),
            "protocol": obj.get("protocol", "tcp"),
        })

    results: List[Dict] = []
    for pi in sorted(found, key=lambda p: p["port"]):
        dangerous = pi["port"] in DANGEROUS_PORTS
        data = {
            "port": pi["port"], "state": "open", "ip": pi["ip"],
            "host": pi["host"], "protocol": pi["protocol"],
            "scan_engine": "naabu", "opsec": opsec,
        }
        if dangerous:
            data["warning"] = DANGEROUS_PORTS[pi["port"]]
        results.append({
            "type": "open_port",
            "source": "naabu",
            "data": data,
            "confidence": 1.0,
            "relevance_score": 0.9 if dangerous else 0.6,
            "tags": ["port", "network"] + (["dangerous", "high_risk"] if dangerous else []),
            "is_anomaly": dangerous,
        })
    if results:
        ports = sorted(p["port"] for p in found)
        results.append({
            "type": "port_scan_summary",
            "source": "naabu",
            "data": {
                "target": target, "host": host, "open_count": len(found),
                "scan_engine": "naabu", "open_ports": ports,
                "dangerous_ports": [
                    {"port": p, "warning": DANGEROUS_PORTS[p]}
                    for p in ports if p in DANGEROUS_PORTS
                ],
                "opsec": opsec,
            },
            "confidence": 1.0,
            "relevance_score": 1.0,
            "tags": ["summary", "port_scan"],
        })
    return results


class NaabuTool(ExternalTool):
    BINARY = "naabu"
    PROXY_FLAG = None          # raw-socket fast scan — honestly attributable
    TIMEOUT = 600.0

    def command(self, target: str, opts: Dict) -> List[str]:
        cmd = ["naabu", "-host", host_only(target), "-json", "-silent", "-duc"]
        ports = opts.get("ports")
        if ports:
            cmd += ["-p", str(ports)]
        else:
            top = self.config.get("port_scan", "top_ports", default=None)
            if top:
                cmd += ["-top-ports", str(top)]
        rate = self.config.get("port_scan", "rate", default=None)
        if rate:
            cmd += ["-rate", str(rate)]
        return cmd

    def parse(self, stdout: str, opsec: str) -> List[Dict]:
        return parse_naabu(stdout, host_only(self._target), opsec)

    async def run(self, target: str, opts=None) -> List[Dict]:
        self._target = target
        return await super().run(target, opts)


def run_naabu_or_native(config, target: str, opts: Dict):
    """Coroutine: naabu when present, else the native port scanner."""
    from phantomsignal.scrapers.port_scanner import PortScanner

    tool = NaabuTool(config)

    def _native():
        return PortScanner(config).scan(
            target, opts.get("ports"),
            stealth=opts.get("stealth"),
            decoys=opts.get("decoys"),
            zombie=opts.get("zombie"),
        )

    return run_with_fallback(tool, target, opts or {}, _native)
