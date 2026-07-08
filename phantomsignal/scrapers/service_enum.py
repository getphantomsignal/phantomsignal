"""
PhantomSignal Service Enumeration — Classic Port Enumeration (Phrack/textfiles)

Phase 3. PhantomSignal already flags ports 25/139/445/161 as "dangerous" but never
enumerates them. This module revives the classic footprinting canon for the two
services we can enumerate correctly from scratch:

  * SMTP (25) — VRFY / EXPN / RCPT-TO user enumeration and an open-relay check.
    Plain-text protocol, so this is exact and fully testable.
  * SNMP (161/udp) — community-string enumeration via a hand-built SNMPv1
    GetRequest for sysDescr.0; a valid community leaks the device description.
    The request encoder is validated against the canonical "public" packet.

NetBIOS/SMB null-session enumeration (139/445) is intentionally *not* here: doing
it correctly needs a real SMB stack (impacket), and a hand-rolled version would be
the kind of silently-wrong protocol code we refuse to ship. It's a documented
follow-up.

Everything active here is enumeration-grade and in-scope for authorised testing
only — the same rule as the rest of PhantomSignal.

Design: response classification and packet encode/parse are pure, unit-tested
functions; socket I/O lives in the class.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("phantomsignal.scrapers.service_enum")

# Small, high-signal username probe list for SMTP enumeration.
SMTP_USERS = [
    "root", "admin", "administrator", "postmaster", "webmaster", "info",
    "support", "sales", "contact", "help", "test", "user", "mail", "office",
    "hr", "security", "noreply", "no-reply", "marketing", "abuse",
]

# Community strings to try for SNMP.
SNMP_COMMUNITIES = ["public", "private", "manager", "community", "cisco", "admin"]

# sysDescr.0 — OID 1.3.6.1.2.1.1.1.0, BER-encoded object identifier body.
_OID_SYSDESCR = bytes.fromhex("2b06010201010100")


# ── SMTP response classification (pure) ─────────────────────────────────────

def classify_vrfy(code: int) -> str:
    """Interpret an SMTP VRFY/RCPT reply code → 'valid' | 'invalid' | 'unknown'."""
    if code in (250, 251):
        return "valid"                      # mailbox exists / will forward
    if code in (550, 551, 553, 501, 502, 252, 500):
        # 550/551/553 no such user; 501 bad syntax; 502/252 VRFY disabled/can't verify
        return "invalid" if code in (550, 551, 553) else "unknown"
    return "unknown"


def parse_smtp_code(line: str) -> Optional[int]:
    """Leading 3-digit status code of an SMTP reply line, or None."""
    line = (line or "").strip()
    if len(line) >= 3 and line[:3].isdigit():
        return int(line[:3])
    return None


def is_open_relay(mail_code: int, rcpt_code: int) -> bool:
    """A foreign MAIL FROM + foreign RCPT TO both accepted (2xx) ⇒ open relay."""
    return 200 <= mail_code < 300 and 200 <= rcpt_code < 300


# ── SNMP v1 GetRequest (pure encode/decode) ─────────────────────────────────

def _ber_len(n: int) -> bytes:
    """BER definite length. Short form for <128, long form otherwise."""
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(value)) + value


def build_snmp_get(community: str, oid_body: bytes = _OID_SYSDESCR,
                   request_id: int = 0) -> bytes:
    """
    Build an SNMPv1 GetRequest. Encoding matches the canonical reference packet:
    community "public" for sysDescr.0 with request_id 0 produces the documented
    43-byte packet (see tests).
    """
    varbind = _ber_tlv(0x30,                       # varbind SEQUENCE
                       _ber_tlv(0x06, oid_body) +  # OID
                       _ber_tlv(0x05, b""))        # NULL value
    varbind_list = _ber_tlv(0x30, varbind)
    pdu_body = (
        _ber_tlv(0x02, request_id.to_bytes(4, "big")) +  # request-id (4 bytes)
        _ber_tlv(0x02, b"\x00") +                          # error-status
        _ber_tlv(0x02, b"\x00") +                          # error-index
        varbind_list
    )
    pdu = _ber_tlv(0xA0, pdu_body)                  # GetRequest PDU (context 0)
    message = (
        _ber_tlv(0x02, b"\x00") +                   # version: 0 (SNMPv1)
        _ber_tlv(0x04, community.encode()) +        # community
        pdu
    )
    return _ber_tlv(0x30, message)                  # outer SEQUENCE


def parse_snmp_sysdescr(data: bytes) -> Optional[str]:
    """
    Pull the first OCTET STRING value out of an SNMP GetResponse's varbind — for
    a sysDescr.0 query that's the device description. Returns None if the packet
    isn't a valid SNMP response or carries an error-status.
    """
    if not data or data[0] != 0x30:
        return None
    try:
        i = 0

        def read_tlv(buf: bytes, pos: int) -> Tuple[int, bytes, int]:
            tag = buf[pos]
            ln = buf[pos + 1]
            pos += 2
            if ln & 0x80:
                nb = ln & 0x7F
                ln = int.from_bytes(buf[pos:pos + nb], "big")
                pos += nb
            return tag, buf[pos:pos + ln], pos + ln

        _, msg, _ = read_tlv(data, 0)               # unwrap outer SEQUENCE
        pos = 0
        _, _ver, pos = read_tlv(msg, pos)           # version
        _, _comm, pos = read_tlv(msg, pos)          # community
        pdu_tag, pdu, _ = read_tlv(msg, pos)        # PDU (0xA2 = GetResponse)
        if pdu_tag not in (0xA2, 0xA0):
            return None
        p = 0
        _, _rid, p = read_tlv(pdu, p)
        _, err, p = read_tlv(pdu, p)
        if err and err[0] != 0:                     # error-status != noError
            return None
        _, _erridx, p = read_tlv(pdu, p)
        _, vblist, _ = read_tlv(pdu, p)             # varbind-list SEQUENCE
        _, vb, _ = read_tlv(vblist, 0)              # first varbind SEQUENCE
        q = 0
        _, _oid, q = read_tlv(vb, q)                # OID
        vtag, val, _ = read_tlv(vb, q)              # value
        if vtag == 0x04:                            # OCTET STRING
            return val.decode(errors="replace")
        return None
    except Exception:
        return None


# ── enumerator ──────────────────────────────────────────────────────────────

class ServiceEnumerator:
    def __init__(self, config):
        self.config = config

    async def run(self, target: str) -> List[Dict]:
        host, domain = self._resolve(target)
        if not host:
            return []
        logger.info("Service enumeration for %s", host)
        results: List[Dict] = []

        smtp_host = await self._smtp_host(domain) or host
        results += await self._enumerate_smtp(smtp_host, domain or smtp_host)
        results += await asyncio.get_event_loop().run_in_executor(
            None, self._enumerate_snmp, host)
        return results

    # ── SMTP ─────────────────────────────────────────────────────────────────
    async def _enumerate_smtp(self, host: str, domain: str) -> List[Dict]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 25), timeout=8)
        except Exception as e:
            logger.debug("SMTP connect failed %s: %s", host, e)
            return []

        results: List[Dict] = []
        try:
            await asyncio.wait_for(reader.readline(), timeout=6)   # banner
            await self._smtp_cmd(reader, writer, f"EHLO phantomsignal.local")

            valid: List[str] = []
            vrfy_supported = False
            for user in SMTP_USERS:
                code = await self._smtp_cmd(reader, writer, f"VRFY {user}")
                if code is None:
                    continue
                verdict = classify_vrfy(code)
                if code not in (502, 252, 500):
                    vrfy_supported = True
                if verdict == "valid":
                    valid.append(user)

            # If VRFY is disabled, fall back to RCPT TO enumeration.
            if not vrfy_supported and domain:
                await self._smtp_cmd(reader, writer,
                                     "MAIL FROM:<probe@phantomsignal.local>")
                for user in SMTP_USERS:
                    code = await self._smtp_cmd(reader, writer,
                                                f"RCPT TO:<{user}@{domain}>")
                    if code is not None and classify_vrfy(code) == "valid":
                        valid.append(user)
                    await self._smtp_cmd(reader, writer, "RSET")

            # Open-relay check (foreign sender + foreign recipient).
            mail_code = await self._smtp_cmd(
                reader, writer, "MAIL FROM:<relay-test@example.net>")
            rcpt_code = await self._smtp_cmd(
                reader, writer, "RCPT TO:<relay-test@example.org>")
            relay = (mail_code is not None and rcpt_code is not None
                     and is_open_relay(mail_code, rcpt_code))
            await self._smtp_cmd(reader, writer, "QUIT")

            valid = sorted(set(valid))
            if valid:
                results.append({
                    "type": "smtp_users",
                    "source": "service_enum",
                    "data": {"host": host, "domain": domain,
                             "valid_users": valid,
                             "method": "VRFY" if vrfy_supported else "RCPT"},
                    "confidence": 0.85, "relevance_score": 0.85,
                    "tags": ["smtp", "enumeration", "users"], "is_anomaly": True,
                })
            if relay:
                results.append({
                    "type": "smtp_open_relay",
                    "source": "service_enum",
                    "data": {"host": host,
                             "detail": "MAIL FROM + RCPT TO for foreign domains accepted"},
                    "confidence": 0.8, "relevance_score": 0.95,
                    "tags": ["smtp", "open-relay", "misconfig"], "is_anomaly": True,
                })
        finally:
            try:
                writer.close()
            except Exception:
                pass
        return results

    async def _smtp_cmd(self, reader, writer, cmd: str) -> Optional[int]:
        try:
            writer.write((cmd + "\r\n").encode())
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=6)
            return parse_smtp_code(line.decode(errors="replace"))
        except Exception:
            return None

    # ── SNMP ─────────────────────────────────────────────────────────────────
    def _enumerate_snmp(self, host: str) -> List[Dict]:
        results: List[Dict] = []
        for community in SNMP_COMMUNITIES:
            sysdescr = self._snmp_query(host, community)
            if sysdescr is not None:
                results.append({
                    "type": "snmp_community",
                    "source": "service_enum",
                    "data": {"host": host, "community": community,
                             "sys_descr": sysdescr[:400]},
                    "confidence": 0.9, "relevance_score": 0.9,
                    "tags": ["snmp", "enumeration", "community"]
                            + (["default-community"] if community in ("public", "private") else []),
                    "is_anomaly": True,
                })
                break   # one valid community is enough to prove exposure
        return results

    def _snmp_query(self, host: str, community: str) -> Optional[str]:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(build_snmp_get(community), (host, 161))
            data, _ = sock.recvfrom(4096)
            return parse_snmp_sysdescr(data)
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug("SNMP query %s/%s failed: %s", host, community, e)
            return None
        finally:
            if sock:
                sock.close()

    # ── target resolution ────────────────────────────────────────────────────
    def _resolve(self, target: str) -> Tuple[Optional[str], Optional[str]]:
        t = (target or "").strip().lower()
        t = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].split("@")[-1]
        if not t:
            return None, None
        # crude ip vs domain: an all-numeric-dotted string is an IP
        is_ip = all(p.isdigit() for p in t.split(".")) and t.count(".") == 3
        return t, (None if is_ip else t)

    async def _smtp_host(self, domain: Optional[str]) -> Optional[str]:
        if not domain:
            return None
        try:
            import dns.resolver
            answers = await asyncio.get_event_loop().run_in_executor(
                None, lambda: dns.resolver.resolve(domain, "MX"))
            mx = sorted(answers, key=lambda r: r.preference)
            return str(mx[0].exchange).rstrip(".") if mx else None
        except Exception:
            return None
