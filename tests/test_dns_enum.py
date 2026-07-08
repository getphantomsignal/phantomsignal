"""Tests for classic DNS enumeration extensions (Phase 3).

Live NSEC/cache-snoop validation is impossible in this sandbox (outbound UDP/53
to arbitrary nameservers is blocked), so the error-prone logic — the walk driver
and the NSEC/NSEC3 record parsing — is validated against crafted records instead.
"""
import dns.message
import dns.rrset
import dns.rdatatype

from phantomsignal.scrapers.dns_recon import hosts_in_24, nsec_walk_names, DNSRecon


def test_hosts_in_24():
    hosts = hosts_in_24("192.0.2.5")
    assert len(hosts) == 254                 # .1 .. .254 (no network/broadcast)
    assert hosts[0] == "192.0.2.1"
    assert hosts[-1] == "192.0.2.254"
    assert "192.0.2.0" not in hosts and "192.0.2.255" not in hosts
    assert hosts_in_24("not-an-ip") == []


def test_nsec_walk_collects_zone():
    # simulated NSEC chain: apex -> a -> b -> c -> (wrap to apex)
    chain = {
        "example.com": "a.example.com",
        "a.example.com": "b.example.com",
        "b.example.com": "c.example.com",
        "c.example.com": "example.com",     # wraps back to apex → stop
    }
    names = nsec_walk_names(lambda n: chain.get(n), "example.com")
    assert names == {"a.example.com", "b.example.com", "c.example.com"}


def test_nsec_walk_terminates_on_loop_and_missing():
    # a pathological loop a -> b -> a must not spin forever
    loop = {"example.com": "a.example.com", "a.example.com": "b.example.com",
            "b.example.com": "a.example.com"}
    names = nsec_walk_names(lambda n: loop.get(n), "example.com")
    assert names == {"a.example.com", "b.example.com"}
    # next_of returning None stops immediately
    assert nsec_walk_names(lambda n: None, "example.com") == set()


def test_nsec_walk_ignores_out_of_zone_next():
    chain = {"example.com": "a.example.com",
             "a.example.com": "evil.org",      # out of zone → recorded? no
             "evil.org": "example.com"}
    names = nsec_walk_names(lambda n: chain.get(n), "example.com")
    assert names == {"a.example.com"}          # evil.org excluded from in-zone set


def _msg_with(rrset):
    m = dns.message.Message()
    m.authority.append(rrset)
    return m


def test_extract_nsec():
    rr = dns.rrset.from_text("a.example.com.", 300, "IN", "NSEC",
                             "b.example.com. A RRSIG NSEC")
    owner, nxt = DNSRecon._extract_nsec(_msg_with(rr))
    assert owner == "a.example.com"
    assert nxt == "b.example.com"
    # no NSEC present → None
    a = dns.rrset.from_text("example.com.", 300, "IN", "A", "1.2.3.4")
    assert DNSRecon._extract_nsec(_msg_with(a)) is None


def test_has_nsec3():
    nsec3 = dns.rrset.from_text(
        "abcdef.example.com.", 300, "IN", "NSEC3PARAM", "1 0 10 abcd")
    assert DNSRecon._has_nsec3(_msg_with(nsec3)) is True
    a = dns.rrset.from_text("example.com.", 300, "IN", "A", "1.2.3.4")
    assert DNSRecon._has_nsec3(_msg_with(a)) is False
