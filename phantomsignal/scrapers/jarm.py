"""
PhantomSignal JARM — Active TLS-Stack Fingerprinting (from scratch)

A clean-room reimplementation of the Salesforce JARM algorithm, validated
against the canonical reference (Google's fingerprint reproduces the documented
`27d40d40d29d40d1dc42d43d00041d…` cipher/version prefix byte-for-byte).

JARM sends ten deliberately-varied TLS Client Hellos and fuzzy-hashes how the
server responds to each. Two servers with the same TLS stack + configuration
produce the same JARM, which makes it a strong infrastructure-pivot signal
(`ssl.jarm:` in Shodan/Censys). The full walkthrough lives in docs/jarm/.

Layout: everything except the actual socket send/recv is a pure function, so the
packet construction and hashing are unit-tested without the network.

Author:  the-clipper
AI:      Claude (Anthropic)  — reference: github.com/salesforce/jarm (clean-room port)
License: MIT — see LICENSE
"""
from __future__ import annotations

import hashlib
import os
import socket
import struct
from typing import List, Optional

# Each probe: [tls_version, cipher_list, cipher_order, grease, alpn, support, ext_order]
# (the reference carries host+port in slots 0-1; we pass those separately.)
PROBES: List[List[str]] = [
    ["TLS_1.2", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.2_SUPPORT", "REVERSE"],
    ["TLS_1.2", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.2_SUPPORT", "FORWARD"],
    ["TLS_1.2", "ALL", "TOP_HALF", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
    ["TLS_1.2", "ALL", "BOTTOM_HALF", "NO_GREASE", "RARE_APLN", "NO_SUPPORT", "FORWARD"],
    ["TLS_1.2", "ALL", "MIDDLE_OUT", "GREASE", "RARE_APLN", "NO_SUPPORT", "REVERSE"],
    ["TLS_1.1", "ALL", "FORWARD", "NO_GREASE", "APLN", "NO_SUPPORT", "FORWARD"],
    ["TLS_1.3", "ALL", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
    ["TLS_1.3", "ALL", "REVERSE", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
    ["TLS_1.3", "NO1.3", "FORWARD", "NO_GREASE", "APLN", "1.3_SUPPORT", "FORWARD"],
    ["TLS_1.3", "ALL", "MIDDLE_OUT", "GREASE", "APLN", "1.3_SUPPORT", "REVERSE"],
]

_GREASE = ["0a0a", "1a1a", "2a2a", "3a3a", "4a4a", "5a5a", "6a6a", "7a7a",
           "8a8a", "9a9a", "aaaa", "baba", "caca", "dada", "eaea", "fafa"]

# Cipher list offered in the Client Hello (order matters — the server's choice
# from a reordered list is the signal).
_CIPHERS_ALL = [
    "0016", "0033", "0067", "c09e", "c0a2", "009e", "0039", "006b", "c09f",
    "c0a3", "009f", "0045", "00be", "0088", "00c4", "009a", "c008", "c009",
    "c023", "c0ac", "c0ae", "c02b", "c00a", "c024", "c0ad", "c0af", "c02c",
    "c072", "c073", "cca9", "1302", "1301", "cc14", "c007", "c012", "c013",
    "c027", "c02f", "c014", "c028", "c030", "c060", "c061", "c076", "c077",
    "cca8", "1305", "1304", "1303", "cc13", "c011", "000a", "002f", "003c",
    "c09c", "c0a0", "009c", "0035", "003d", "c09d", "c0a1", "009d", "0041",
    "00ba", "0084", "00c0", "0007", "0004", "0005",
]
_TLS13_CIPHERS = {"1301", "1302", "1303", "1304", "1305"}
_CIPHERS_NO13 = [c for c in _CIPHERS_ALL if c not in _TLS13_CIPHERS]

# DIFFERENT, value-sorted list used ONLY to encode the server's chosen cipher
# into the hash. (Using the offer-order list here is the classic mistake — it
# yields a self-consistent but non-canonical fingerprint.)
_CIPHER_HASH = [
    "0004", "0005", "0007", "000a", "0016", "002f", "0033", "0035", "0039",
    "003c", "003d", "0041", "0045", "0067", "006b", "0084", "0088", "009a",
    "009c", "009d", "009e", "009f", "00ba", "00be", "00c0", "00c4", "c007",
    "c008", "c009", "c00a", "c011", "c012", "c013", "c014", "c023", "c024",
    "c027", "c028", "c02b", "c02c", "c02f", "c030", "c060", "c061", "c072",
    "c073", "c076", "c077", "c09c", "c09d", "c09e", "c09f", "c0a0", "c0a1",
    "c0a2", "c0a3", "c0ac", "c0ad", "c0ae", "c0af", "cc13", "cc14", "cca8",
    "cca9", "1301", "1302", "1303", "1304", "1305",
]

_ALL_ZERO_RAW = ",".join(["|||"] * 10)


def _grease() -> str:
    return _GREASE[int.from_bytes(os.urandom(1), "big") % len(_GREASE)]


# ── cipher / list reordering (canonical) ────────────────────────────────────

def cipher_mung(ciphers: List[str], request: str) -> List[str]:
    """Reorder a cipher list per a probe's mode. Matches the reference exactly."""
    n = len(ciphers)
    if request == "REVERSE":
        return ciphers[::-1]
    if request == "BOTTOM_HALF":
        return ciphers[n // 2 + 1:] if n % 2 == 1 else ciphers[n // 2:]
    if request == "TOP_HALF":
        out: List[str] = []
        if n % 2 == 1:
            out.append(ciphers[n // 2])           # middle cipher first
        out += cipher_mung(cipher_mung(ciphers, "REVERSE"), "BOTTOM_HALF")
        return out
    if request == "MIDDLE_OUT":
        mid = n // 2
        out = []
        if n % 2 == 1:
            out.append(ciphers[mid])
            for i in range(1, mid + 1):
                out += [ciphers[mid + i], ciphers[mid - i]]
        else:
            for i in range(1, mid + 1):
                out += [ciphers[mid - 1 + i], ciphers[mid - i]]
        return out
    return ciphers  # FORWARD (never munged)


def _get_ciphers(p: List[str]) -> bytes:
    ciphers = list(_CIPHERS_ALL if p[1] == "ALL" else _CIPHERS_NO13)
    if p[2] != "FORWARD":
        ciphers = cipher_mung(ciphers, p[2])
    if p[3] == "GREASE":
        ciphers.insert(0, _grease())
    return b"".join(bytes.fromhex(c) for c in ciphers)


# ── extension construction ──────────────────────────────────────────────────

def _ext_sni(host: str) -> bytes:
    hb = host.encode()
    inner = b"\x00" + struct.pack(">H", len(hb)) + hb
    slist = struct.pack(">H", len(inner)) + inner
    return b"\x00\x00" + struct.pack(">H", len(slist)) + slist


def _ext_alpn(p: List[str]) -> bytes:
    if p[4] == "RARE_APLN":
        alpns = ["08687474702f302e39", "08687474702f312e30", "06737064792f31",
                 "06737064792f32", "06737064792f33", "03683263", "026871"]
    else:
        alpns = ["08687474702f302e39", "08687474702f312e30", "08687474702f312e31",
                 "06737064792f31", "06737064792f32", "06737064792f33",
                 "026832", "03683263", "026871"]
    if p[6] != "FORWARD":
        alpns = cipher_mung(alpns, p[6])
    body = b"".join(bytes.fromhex(a) for a in alpns)
    return b"\x00\x10" + struct.pack(">H", len(body) + 2) + struct.pack(">H", len(body)) + body


def _ext_key_share(grease: bool) -> bytes:
    share = b""
    if grease:
        share += bytes.fromhex(_grease()) + b"\x00\x01\x00"
    share += b"\x00\x1d" + b"\x00\x20" + os.urandom(32)   # group x25519 + 32-byte key
    return b"\x00\x33" + struct.pack(">H", len(share) + 2) + struct.pack(">H", len(share)) + share


def _ext_supported_versions(p: List[str], grease: bool) -> bytes:
    tls = ["0301", "0302", "0303"] if p[5] == "1.2_SUPPORT" else ["0301", "0302", "0303", "0304"]
    if p[6] != "FORWARD":
        tls = cipher_mung(tls, p[6])
    body = (bytes.fromhex(_grease()) if grease else b"") + b"".join(bytes.fromhex(v) for v in tls)
    return b"\x00\x2b" + struct.pack(">H", len(body) + 1) + struct.pack(">B", len(body)) + body


def _get_extensions(host: str, p: List[str]) -> bytes:
    grease = p[3] == "GREASE"
    e = b""
    if grease:
        e += bytes.fromhex(_grease()) + b"\x00\x00"
    e += _ext_sni(host)
    e += b"\x00\x17\x00\x00"                                  # extended_master_secret
    e += b"\x00\x01\x00\x01\x01"                              # max_fragment_length
    e += b"\xff\x01\x00\x01\x00"                              # renegotiation_info
    e += b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"  # supported_groups
    e += b"\x00\x0b\x00\x02\x01\x00"                          # ec_point_formats
    e += b"\x00\x23\x00\x00"                                  # session_ticket
    e += _ext_alpn(p)
    e += (b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03"
          b"\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01")        # signature_algorithms
    e += _ext_key_share(grease)
    e += b"\x00\x2d\x00\x02\x01\x01"                          # psk_key_exchange_modes
    if p[0] == "TLS_1.3" or p[5] == "1.2_SUPPORT":           # conditional!
        e += _ext_supported_versions(p, grease)
    return struct.pack(">H", len(e)) + e


def build_client_hello(host: str, p: List[str]) -> bytes:
    """Assemble one JARM probe's TLS record. Pure — no network."""
    record_ver = {"TLS_1.3": b"\x03\x01", "TLS_1.2": b"\x03\x03",
                  "TLS_1.1": b"\x03\x02", "TLS_1": b"\x03\x01", "SSLv3": b"\x03\x00"}[p[0]]
    hello_ver = b"\x03\x03" if p[0] == "TLS_1.3" else record_ver
    ciphers = _get_ciphers(p)
    ch = hello_ver + os.urandom(32)
    ch += b"\x20" + os.urandom(32)                            # 32-byte session id
    ch += struct.pack(">H", len(ciphers)) + ciphers
    ch += b"\x01\x00"                                         # 1 compression method: null
    ch += _get_extensions(host, p)
    handshake = b"\x01" + b"\x00" + struct.pack(">H", len(ch)) + ch
    return b"\x16" + record_ver + struct.pack(">H", len(handshake)) + handshake


# ── ServerHello parsing → per-probe token ───────────────────────────────────

def _find_alpn(types: List[bytes], values: List[bytes]) -> str:
    for t, v in zip(types, values):
        if t == b"\x00\x10" and len(v) >= 3:
            return v[3:].decode(errors="ignore")
    return ""


def read_server_hello(data: bytes) -> str:
    """Parse a ServerHello into JARM's ``cipher|version|alpn|ext-types`` token."""
    if not data:
        return "|||"
    if data[0] == 0x15:                                      # TLS alert
        return "|||"
    if not (data[0] == 0x16 and len(data) > 5 and data[5] == 0x02):
        return "|||"
    try:
        counter = data[43]
        cipher = data[counter + 44:counter + 46].hex()
        version = data[9:11].hex()
        ext_len = int.from_bytes(data[counter + 47:counter + 49], "big")
        count = counter + 49
        end = count + ext_len
        types: List[bytes] = []
        values: List[bytes] = []
        while count < end:
            t = data[count:count + 2]
            elen = int.from_bytes(data[count + 2:count + 4], "big")
            types.append(t)
            values.append(data[count + 4:count + 4 + elen] if elen else b"")
            count += elen + 4
        alpn = _find_alpn(types, values)
        ext_hex = "-".join(t.hex() for t in types)
        return f"{cipher}|{version}|{alpn}|{ext_hex}"
    except Exception:
        return "|||"


# ── fuzzy hash ──────────────────────────────────────────────────────────────

def _cipher_code(cipher: str) -> str:
    if cipher == "":
        return "00"
    n = 1
    for c in _CIPHER_HASH:
        if c == cipher:
            break
        n += 1
    h = format(n, "x")
    return h if len(h) >= 2 else "0" + h


def _version_code(version: str) -> str:
    return "0" if version == "" else "abcdef"[int(version[3:4])]


def jarm_hash(raw: str) -> str:
    """Fuzzy-hash the 10 comma-joined probe tokens into the 62-char JARM."""
    if raw == _ALL_ZERO_RAW:
        return "0" * 62
    fuzzy = ""
    alpns_and_ext = ""
    for token in raw.split(","):
        parts = token.split("|")
        fuzzy += _cipher_code(parts[0])
        fuzzy += _version_code(parts[1]) if len(parts) > 1 else "0"
        alpns_and_ext += (parts[2] if len(parts) > 2 else "")
        alpns_and_ext += (parts[3] if len(parts) > 3 else "")
    fuzzy += hashlib.sha256(alpns_and_ext.encode()).hexdigest()[:32]
    return fuzzy


# ── network driver ──────────────────────────────────────────────────────────

def _probe(host: str, port: int, p: List[str], timeout: float) -> str:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(build_client_hello(host, p))
        return read_server_hello(sock.recv(1484))
    except Exception:
        return "|||"
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def compute_jarm(host: str, port: int = 443, timeout: float = 5.0) -> str:
    """Blocking: run all ten probes and return the 62-char JARM fingerprint."""
    tokens = [_probe(host, port, p, timeout) for p in PROBES]
    return jarm_hash(",".join(tokens))
