"""
PhantomSignal — tlsx adapter (v1.26), a fast TLS-fingerprint path that
complements the native JARM + certificate fingerprinting in infra_pivot.

tlsx (ProjectDiscovery) probes TLS at scale and returns JARM + cert hashes +
SANs. It performs direct TLS handshakes (no proxy), so it is honestly tagged
**attributable**. Findings match infra_pivot's ``jarm_fingerprint`` /
``tls_cert_fingerprint`` shape, feeding the same Shodan pivots. Opt-in: absent
the binary this module simply produces nothing — infra_pivot still does JARM +
cert fingerprinting natively.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List

from phantomsignal.scrapers._external import ExternalTool, host_only

logger = logging.getLogger("phantomsignal.scrapers.tlsx")


def _fp(ftype: str, host: str, value: str, dork: str, extra: Dict) -> Dict:
    return {
        "type": ftype,
        "source": "tlsx",
        "data": {"host": host, "value": value, "shodan_dork": dork, **extra},
        "confidence": 0.95,
        "relevance_score": 0.7,
        "tags": ["infra", "fingerprint", ftype.split("_")[0]],
    }


def parse_tlsx(stdout: str, opsec: str) -> List[Dict]:
    """tlsx ``-json`` lines → infra_pivot-compatible fingerprint findings."""
    results: List[Dict] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        host = obj.get("host") or obj.get("ip")
        if not host:
            continue
        jarm = obj.get("jarm_hash") or obj.get("jarm")
        if jarm:
            results.append(_fp("jarm_fingerprint", host, jarm,
                               f"ssl.jarm:{jarm}", {"opsec": opsec}))
        fh = obj.get("fingerprint_hash")
        sha = fh.get("sha256") if isinstance(fh, dict) else None
        if sha:
            results.append(_fp("tls_cert_fingerprint", host, sha,
                               f"ssl.cert.fingerprint:{sha}",
                               {"opsec": opsec,
                                "san": obj.get("subject_an") or [],
                                "issuer": obj.get("issuer_dn")}))
    return results


class TlsxTool(ExternalTool):
    BINARY = "tlsx"
    PROXY_FLAG = None          # direct TLS handshake — attributable
    TIMEOUT = 300.0

    def command(self, target: str, opts: Dict) -> List[str]:
        return ["tlsx", "-u", host_only(target), "-json", "-silent", "-duc",
                "-jarm", "-cn", "-san", "-hash", "sha256"]

    def parse(self, stdout: str, opsec: str) -> List[Dict]:
        return parse_tlsx(stdout, opsec)
