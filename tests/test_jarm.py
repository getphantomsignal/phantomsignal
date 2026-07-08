"""Tests for the from-scratch JARM implementation (Phase 2 follow-up)."""
from phantomsignal.scrapers.jarm import (
    cipher_mung,
    jarm_hash,
    build_client_hello,
    read_server_hello,
    PROBES,
    _cipher_code,
    _version_code,
)


def test_cipher_mung_matches_reference_semantics():
    lst = [str(i) for i in range(1, 8)]  # odd length 7
    assert cipher_mung(lst, "REVERSE") == ["7", "6", "5", "4", "3", "2", "1"]
    # TOP_HALF = [middle] + BOTTOM_HALF(REVERSE(list))
    assert cipher_mung(lst, "TOP_HALF") == ["4", "3", "2", "1"]
    # BOTTOM_HALF of odd length skips the middle element
    assert cipher_mung(lst, "BOTTOM_HALF") == ["5", "6", "7"]
    assert cipher_mung(lst, "MIDDLE_OUT") == ["4", "5", "3", "6", "2", "7", "1"]
    # FORWARD is never reordered
    assert cipher_mung(lst, "FORWARD") == lst


def test_cipher_mung_even_length():
    lst = [str(i) for i in range(1, 7)]  # even length 6
    assert cipher_mung(lst, "BOTTOM_HALF") == ["4", "5", "6"]
    assert cipher_mung(lst, "MIDDLE_OUT") == ["4", "3", "5", "2", "6", "1"]


def test_cipher_and_version_codes():
    # value-sorted hash list: "0004" is first -> code 01; version 0303 -> 'd'
    assert _cipher_code("0004") == "01"
    assert _cipher_code("") == "00"
    assert _cipher_code("1305") == format(69, "x")   # last entry, index 68 -> 69
    assert _version_code("0303") == "d"
    assert _version_code("0301") == "b"
    assert _version_code("0304") == "e"
    assert _version_code("") == "0"


def test_jarm_hash_all_fail_is_zeros():
    assert jarm_hash(",".join(["|||"] * 10)) == "0" * 62


def test_jarm_hash_length_and_encoding():
    # 10 identical tokens; cipher 0004->01, version 0303->d, so prefix is "01d"*10
    raw = ",".join(["0004|0303|h2|0000-0017"] * 10)
    h = jarm_hash(raw)
    assert len(h) == 62
    assert h[:30] == "01d" * 10
    # tail is a 32-char hex sha256 slice
    assert len(h[30:]) == 32 and all(c in "0123456789abcdef" for c in h[30:])


def test_build_client_hello_is_well_formed():
    for p in PROBES:
        rec = build_client_hello("example.com", p)
        assert rec[0] == 0x16                 # TLS handshake record
        assert rec[5] == 0x01                 # ClientHello handshake type
        # record-declared length matches the actual handshake bytes
        declared = int.from_bytes(rec[3:5], "big")
        assert declared == len(rec) - 5


def test_read_server_hello_rejects_non_hello():
    assert read_server_hello(b"") == "|||"
    assert read_server_hello(b"\x15\x03\x01\x00\x02\x02\x28") == "|||"   # TLS alert
    assert read_server_hello(b"\x16\x03\x03\x00\x10\x0e") == "|||"       # not a ServerHello (0x0e)
