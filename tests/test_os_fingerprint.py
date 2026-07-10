"""Tests for passive OS fingerprinting (Phase 3, port_scanner).

Live SYN-ACK capture needs CAP_NET_RAW (unavailable in the sandbox, and denied to
an unprivileged user), so the error-prone logic — IP/TCP/option byte parsing and
the TTL→OS inference — is validated against hand-built packets instead. The packet
builder here mirrors what a Linux and a Windows host actually put on the wire.
"""
import struct

from phantomsignal.scrapers.port_scanner import (
    snap_initial_ttl, parse_ip_header, parse_tcp_header, parse_tcp_options,
    fingerprint_os,
)


def _ip_header(ttl: int, payload_len: int, src="203.0.113.10", dst="192.0.2.1") -> bytes:
    src_b = bytes(int(o) for o in src.split("."))
    dst_b = bytes(int(o) for o in dst.split("."))
    total = 20 + payload_len
    return (
        bytes([0x45, 0x00])                 # ver/IHL, TOS
        + struct.pack(">H", total)          # total length
        + struct.pack(">H", 0)              # id
        + struct.pack(">H", 0x4000)         # flags (DF) / frag
        + bytes([ttl, 6])                   # TTL, protocol=TCP
        + struct.pack(">H", 0)              # checksum (unchecked)
        + src_b + dst_b
    )


def _tcp_synack(dst_port: int, window: int, options: bytes) -> bytes:
    # pad options to a 4-byte boundary
    if len(options) % 4:
        options += b"\x00" * (4 - len(options) % 4)
    header_len = 20 + len(options)
    data_offset = (header_len // 4) << 4
    return (
        struct.pack(">H", 443)              # src port
        + struct.pack(">H", dst_port)       # dst port
        + struct.pack(">I", 0x11111111)     # seq
        + struct.pack(">I", 0x22222222)     # ack
        + bytes([data_offset, 0x12])        # data offset / reserved, flags=SYN+ACK
        + struct.pack(">H", window)         # window
        + struct.pack(">H", 0)              # checksum
        + struct.pack(">H", 0)              # urgent
        + options
    )


# Real-world option layouts.
_LINUX_OPTS = (
    b"\x02\x04\x05\xb4"                      # MSS 1460
    b"\x04\x02"                             # SACK permitted
    b"\x08\x0a" + b"\x00" * 8               # Timestamps
    + b"\x01"                                # NOP
    b"\x03\x03\x07"                         # Window scale 7
)
_WINDOWS_OPTS = (
    b"\x02\x04\x05\xb4"                      # MSS 1460
    b"\x01"                                 # NOP
    b"\x03\x03\x08"                         # Window scale 8
    b"\x01\x01"                             # NOP NOP
    b"\x04\x02"                             # SACK permitted
)


def _packet(ttl, dst_port, window, options):
    tcp = _tcp_synack(dst_port, window, options)
    return _ip_header(ttl, len(tcp)) + tcp


# ── snap_initial_ttl ────────────────────────────────────────────────────────

def test_snap_initial_ttl_buckets():
    assert snap_initial_ttl(64) == (64, 0)
    assert snap_initial_ttl(54) == (64, 10)      # Linux, 10 hops
    assert snap_initial_ttl(128) == (128, 0)
    assert snap_initial_ttl(117) == (128, 11)    # Windows, 11 hops
    assert snap_initial_ttl(240) == (255, 15)    # network gear


def test_snap_initial_ttl_rejects_implausible():
    # 200 would need 55 hops from 255 → not cleanly bucketable
    assert snap_initial_ttl(200) == (None, None)
    assert snap_initial_ttl(0) == (None, None)


# ── header / option parsing ─────────────────────────────────────────────────

def test_parse_ip_header():
    ip = parse_ip_header(_ip_header(54, 20))
    assert ip["ttl"] == 54 and ip["protocol"] == 6 and ip["ihl"] == 20
    assert ip["src"] == "203.0.113.10"
    assert parse_ip_header(b"\x45\x00") is None          # too short
    assert parse_ip_header(b"\x60" + b"\x00" * 40) is None  # not IPv4


def test_parse_tcp_options_linux():
    opts = parse_tcp_options(_LINUX_OPTS)
    assert opts["mss"] == 1460
    assert opts["window_scale"] == 7
    assert opts["sack_permitted"] is True
    assert opts["timestamps"] is True
    assert opts["order"] == [2, 4, 8, 1, 3]


def test_parse_tcp_options_windows():
    opts = parse_tcp_options(_WINDOWS_OPTS)
    assert opts["mss"] == 1460
    assert opts["window_scale"] == 8
    assert opts["sack_permitted"] is True
    assert opts["timestamps"] is False                    # Windows default
    assert opts["order"] == [2, 1, 3, 1, 1, 4]


def test_parse_tcp_options_malformed_stops_cleanly():
    # a bogus length that would over-read must not raise or run past the buffer
    assert parse_tcp_options(b"\x02\xff\x05\xb4")["order"] == []
    # EOL terminates
    assert parse_tcp_options(b"\x01\x00\x02\x04\x05\xb4")["order"] == [1, 0]


# ── end-to-end fingerprint from a full packet ───────────────────────────────

def _capture(pkt, local_port):
    """Replicate what _capture_syn_ack extracts from a matched packet."""
    ip = parse_ip_header(pkt)
    tcp = parse_tcp_header(pkt[ip["ihl"]:])
    assert tcp["dst_port"] == local_port
    assert (tcp["flags"] & 0x12) == 0x12
    o = parse_tcp_options(tcp["options"])
    return {"observed_ttl": ip["ttl"], "window": tcp["window"], "mss": o["mss"],
            "window_scale": o["window_scale"], "sack_permitted": o["sack_permitted"],
            "timestamps": o["timestamps"], "options_order": o["order"]}


def test_fingerprint_linux_synack():
    pkt = _packet(ttl=54, dst_port=49500, window=28960, options=_LINUX_OPTS)
    fp = fingerprint_os(_capture(pkt, 49500))
    assert fp["initial_ttl"] == 64
    assert fp["hop_count"] == 10
    assert "Linux" in fp["os_family"]
    assert fp["mss"] == 1460 and fp["tcp_window"] == 28960
    # timestamps + SACK on a TTL-64 host bumps confidence above the 0.65 base
    assert fp["confidence"] > 0.65
    assert any("timestamps" in e for e in fp["evidence"])


def test_fingerprint_windows_synack():
    pkt = _packet(ttl=117, dst_port=52000, window=65535, options=_WINDOWS_OPTS)
    fp = fingerprint_os(_capture(pkt, 52000))
    assert fp["initial_ttl"] == 128
    assert fp["os_family"] == "Windows"
    assert fp["timestamps"] is False
    assert any("Windows defaults" in e for e in fp["evidence"])


def test_fingerprint_rejects_unbucketable_ttl():
    assert fingerprint_os({"observed_ttl": 200}) is None
    assert fingerprint_os({}) is None
