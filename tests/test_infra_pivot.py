"""Tests for infra pivot — favicon hash & TLS cert fingerprinting (Phase 2)."""
import base64

from phantomsignal.scrapers.infra_pivot import (
    murmur3_x86_32,
    shodan_favicon_hash,
    find_favicon_url,
    cert_sha256,
    sans_from_cert,
)


def test_murmur3_known_vectors():
    # Ground truth captured from the reference `mmh3` package.
    assert murmur3_x86_32(b"") == 0
    assert murmur3_x86_32(b"test") == -1167338989
    assert murmur3_x86_32(b"a") == 1009084850
    assert murmur3_x86_32(b"abc") == -1277324294
    assert murmur3_x86_32(bytes(range(50))) == 284514547


def test_shodan_favicon_hash():
    # mmh3.hash(base64.encodebytes(b"hello")) == 1155597304
    assert shodan_favicon_hash(b"hello") == 1155597304
    # matches the documented compose: base64 with MIME newlines, then murmur3
    assert shodan_favicon_hash(b"hello") == murmur3_x86_32(base64.encodebytes(b"hello"))


def test_find_favicon_url():
    html = '<html><head><link rel="shortcut icon" href="/assets/fav.png"></head></html>'
    assert find_favicon_url(html, "https://acme.com/") == "https://acme.com/assets/fav.png"
    # absolute href preserved
    html2 = '<link rel="icon" href="https://cdn.acme.com/f.ico">'
    assert find_favicon_url(html2, "https://acme.com/") == "https://cdn.acme.com/f.ico"
    # no link → default /favicon.ico
    assert find_favicon_url("<html></html>", "https://acme.com/") == "https://acme.com/favicon.ico"


def test_cert_sha256():
    fp = cert_sha256(b"dummy-der-bytes")
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)


def test_sans_from_cert_scopes_to_domain():
    cert = {"subjectAltName": (
        ("DNS", "acme.com"),
        ("DNS", "*.api.acme.com"),
        ("DNS", "www.acme.com"),
        ("DNS", "cdn.evil.com"),      # out of scope
        ("IP Address", "1.2.3.4"),    # wrong type
    )}
    sans = sans_from_cert(cert, "acme.com")
    assert sans == {"acme.com", "api.acme.com", "www.acme.com"}
    assert "cdn.evil.com" not in sans
