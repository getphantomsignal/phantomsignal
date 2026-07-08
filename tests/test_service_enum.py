"""Tests for service enumeration — SMTP + SNMP (Phase 3)."""
from phantomsignal.scrapers.service_enum import (
    classify_vrfy,
    parse_smtp_code,
    is_open_relay,
    build_snmp_get,
    parse_snmp_sysdescr,
    _ber_tlv,
    _ber_len,
    _OID_SYSDESCR,
)

# Canonical SNMPv1 GetRequest for sysDescr.0 with community "public", req-id 0.
_REF_SNMP_GET = bytes.fromhex(
    "302902010004067075626c6963a01c020400000000020100020100300e300c06082b060102010101000500")


def test_classify_vrfy():
    assert classify_vrfy(250) == "valid"
    assert classify_vrfy(251) == "valid"
    assert classify_vrfy(550) == "invalid"
    assert classify_vrfy(551) == "invalid"
    assert classify_vrfy(252) == "unknown"     # cannot verify
    assert classify_vrfy(502) == "unknown"     # VRFY disabled
    assert classify_vrfy(500) == "unknown"


def test_parse_smtp_code():
    assert parse_smtp_code("250 2.1.5 Sender OK") == 250
    assert parse_smtp_code("550-No such user") == 550
    assert parse_smtp_code("banner text") is None
    assert parse_smtp_code("") is None


def test_open_relay():
    assert is_open_relay(250, 250) is True
    assert is_open_relay(250, 550) is False
    assert is_open_relay(550, 250) is False


def test_ber_length_encoding():
    assert _ber_len(5) == b"\x05"           # short form
    assert _ber_len(0x7F) == b"\x7f"
    assert _ber_len(0x80) == b"\x81\x80"    # long form, 1 length byte
    assert _ber_len(300) == b"\x82\x01\x2c"


def test_snmp_get_matches_canonical_packet():
    # The definitive validation: our encoder reproduces the documented packet.
    assert build_snmp_get("public", request_id=0) == _REF_SNMP_GET


def test_snmp_get_varies_by_community():
    priv = build_snmp_get("private", request_id=0)
    assert b"private" in priv
    assert priv != _REF_SNMP_GET
    assert priv[0] == 0x30                   # still a valid outer SEQUENCE


def test_snmp_response_roundtrip():
    # Build a GetResponse with the same encoder and confirm the parser extracts it.
    def response(community, sysdescr, err=0):
        vb = _ber_tlv(0x30, _ber_tlv(0x06, _OID_SYSDESCR) + _ber_tlv(0x04, sysdescr.encode()))
        pdu_body = (_ber_tlv(0x02, b"\x00\x00\x00\x00") + _ber_tlv(0x02, bytes([err]))
                    + _ber_tlv(0x02, b"\x00") + _ber_tlv(0x30, vb))
        pdu = _ber_tlv(0xA2, pdu_body)       # GetResponse
        msg = _ber_tlv(0x02, b"\x00") + _ber_tlv(0x04, community.encode()) + pdu
        return _ber_tlv(0x30, msg)

    assert parse_snmp_sysdescr(response("public", "Linux router 5.10")) == "Linux router 5.10"
    # error-status set → None
    assert parse_snmp_sysdescr(response("public", "x", err=2)) is None
    # non-SNMP bytes → None
    assert parse_snmp_sysdescr(b"\x16\x03\x03not-snmp") is None
    assert parse_snmp_sysdescr(b"") is None
