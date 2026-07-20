"""Tests for the keyless identity intel sources.

Pure parsers + identifier detection + offline phone intel are tested directly.
The network classes are driven through an httpx MockTransport so no real
requests are made. Registration + no-key posture is asserted for all eight.
"""
import httpx
import pytest

from phantomsignal.intel.apis import shodan_api, all_apis  # noqa: F401
from phantomsignal.intel.apis.base import get_registered_apis, APICategory
from phantomsignal.intel.apis import identity_sources as S


class _Cfg:
    def get_api_key(self, *_a, **_k):
        return None

    def get(self, *_a, **k):
        return k.get("default")


# ── identifier detection ──────────────────────────────────────────────────────

@pytest.mark.parametrize("q,email,phone,user,name", [
    ("jane@example.com", True, False, False, False),
    ("+1 415-555-2671", False, True, False, False),
    ("14155552671", False, True, True, False),   # digits also look like a handle
    ("jane_dev", False, False, True, False),
    ("Jane Doe", False, False, False, True),
    ("", False, False, False, False),
])
def test_identifier_detection(q, email, phone, user, name):
    assert S.is_email(q) is email
    assert S.is_phone(q) is phone
    assert S.is_username(q) is user
    assert S.looks_like_name(q) is name


# ── XposedOrNot ───────────────────────────────────────────────────────────────

def test_parse_xposed_breach_details():
    payload = {"ExposedBreaches": {"breaches_details": [
        {"breach": "BigLeak", "xposed_date": "2019", "xposed_records": 1000,
         "xposed_data": "Emails;Passwords;Usernames", "domain": "big.com"},
    ]}}
    out = S.parse_xposed(payload, "j@example.com")
    assert out[0]["name"] == "BigLeak"
    assert out[0]["pwn_count"] == 1000
    assert out[0]["data_classes"] == ["Emails", "Passwords", "Usernames"]


def test_parse_xposed_summary_fallback():
    out = S.parse_xposed({"BreachesSummary": {"site": "A;B;C"}}, "j@example.com")
    assert {b["name"] for b in out} == {"A", "B", "C"}


def test_parse_xposed_empty_and_error():
    assert S.parse_xposed({"Error": "Not found"}, "j@example.com") == []
    assert S.parse_xposed("junk", "j@example.com") == []


# ── Wikidata ──────────────────────────────────────────────────────────────────

def _human_entity(qid="Q42"):
    return {"entities": {qid: {
        "labels": {"en": {"value": "Jane Doe"}},
        "descriptions": {"en": {"value": "British engineer"}},
        "claims": {
            "P31": [{"mainsnak": {"datavalue": {"value": {"id": "Q5"}}}}],
            "P569": [{"mainsnak": {"datavalue": {"value": {"time": "+1971-03-11T00:00:00Z"}}}}],
            "P856": [{"mainsnak": {"datavalue": {"value": "https://jane.example"}}}],
            "P2037": [{"mainsnak": {"datavalue": {"value": "janedoe"}}}],
        },
    }}}


def test_parse_wikidata_human():
    data = S.parse_wikidata(_human_entity(), "Q42")
    assert data["names"] == ["Jane Doe"]
    assert data["dob"] == "1971"
    urls = {u["url"] for u in data["urls"]}
    assert "https://jane.example" in urls
    assert "https://github.com/janedoe" in urls


def test_parse_wikidata_rejects_nonhuman():
    entity = _human_entity()
    entity["entities"]["Q42"]["claims"]["P31"] = [
        {"mainsnak": {"datavalue": {"value": {"id": "Q11424"}}}}  # film
    ]
    assert S.parse_wikidata(entity, "Q42") is None


# ── openFEC / OpenCorporates / GitLab / WebFinger parsers ─────────────────────

def test_parse_fec_dedups_and_filters():
    results = [
        {"contributor_name": "JANE DOE", "contributor_employer": "CorpCo",
         "contributor_occupation": "ENGINEER", "contributor_city": "denver",
         "contributor_state": "CO", "contributor_zip": "80202"},
        {"contributor_name": "JANE DOE", "contributor_employer": "RETIRED",
         "contributor_city": "denver", "contributor_state": "CO"},
    ]
    data = S.parse_fec(results, "Jane Doe")
    assert data["employers"] == ["CorpCo"]         # RETIRED filtered out
    assert data["occupation"] == "ENGINEER"
    assert data["location"] == "Denver, CO"
    assert data["addresses"][0]["zip"] == "80202"


def test_parse_fec_empty():
    assert S.parse_fec([], "Jane Doe") is None


def test_parse_opencorporates():
    payload = {"results": {"officers": [
        {"officer": {"name": "Jane Doe", "position": "director",
                     "company": {"name": "CorpCo", "jurisdiction_code": "us_de",
                                 "opencorporates_url": "https://oc/CorpCo"}}},
    ]}}
    data = S.parse_opencorporates(payload, "Jane Doe")
    assert data["employers"][0]["name"] == "CorpCo"
    assert data["employers"][0]["role"] == "director"
    assert data["urls"] == [{"url": "https://oc/CorpCo"}]


def test_parse_gitlab():
    data = S.parse_gitlab({"username": "jane", "name": "Jane Doe",
                           "public_email": "jane@example.com", "location": "Berlin",
                           "organization": "CorpCo", "web_url": "https://gitlab.com/jane"})
    assert data["emails"] == ["jane@example.com"]
    assert data["company"] == "CorpCo"
    assert {"url": "https://gitlab.com/jane"} in data["urls"]


def test_parse_webfinger():
    payload = {"subject": "acct:jane@mastodon.example",
               "aliases": ["https://mastodon.example/@jane"],
               "links": [{"rel": "http://webfinger.net/rel/profile-page",
                          "href": "https://mastodon.example/@jane"},
                         {"rel": "other", "href": "https://ignore"}]}
    data = S.parse_webfinger(payload)
    assert data["urls"] == [{"url": "https://mastodon.example/@jane"}]
    assert data["aliases"] == ["https://mastodon.example/@jane"]


def test_parse_webfinger_empty():
    assert S.parse_webfinger({"links": []}) is None


# ── offline phone intel (real libphonenumber, no network) ─────────────────────

def test_phone_intel_valid_us():
    out = S.phone_intel("+1 415-555-2671")
    assert out and out[0]["type"] == "phone_validation"
    d = out[0]["data"]
    assert d["valid"] is True and d["region_code"] == "US"
    assert d["source_offline"] is True


def test_phone_intel_rejects_nonphone():
    assert S.phone_intel("jane@example.com") == []
    assert S.phone_intel("123") == []


# ── network classes via MockTransport ─────────────────────────────────────────

def _mock_stealth(handler):
    """A StealthClient whose direct egress is a MockTransport — lets us drive a
    STEALTH_ROUTED source end-to-end without real network."""
    from phantomsignal.core.http import StealthClient, PROFILES
    sc = StealthClient(profile=PROFILES["off"], pool=[None])
    sc._clients[None] = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return sc


@pytest.mark.asyncio
async def test_xposed_api_end_to_end():
    def handler(request):
        assert "breach-analytics" in str(request.url)
        return httpx.Response(200, json={"ExposedBreaches": {"breaches_details": [
            {"breach": "BigLeak", "xposed_date": "2019",
             "xposed_data": "Emails;Passwords"}]}})

    api = S.XposedOrNotAPI(_Cfg())
    api._stealth = _mock_stealth(handler)
    out = await api.search("jane@example.com")
    assert out[0]["type"] == "breach_data"
    assert out[0]["data"]["breaches"][0]["name"] == "BigLeak"
    # wrong identifier shape → no request, empty
    assert await api.search("not-an-email") == []


@pytest.mark.asyncio
async def test_gitlab_api_end_to_end():
    def handler(request):
        if request.url.path == "/api/v4/users":
            return httpx.Response(200, json=[{"id": 7, "username": "jane"}])
        return httpx.Response(200, json={"username": "jane", "name": "Jane Doe",
                                         "public_email": "jane@example.com"})

    api = S.GitLabAPI(_Cfg())
    api._stealth = _mock_stealth(handler)
    out = await api.search("jane")
    assert out[0]["data"]["emails"] == ["jane@example.com"]


# ── stealth routing ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stealth_routed_records_proxied_egress():
    """A STEALTH_ROUTED source must egress through the proxy pool and land in the
    attribution ledger as proxied — not leak direct + unrecorded."""
    from phantomsignal.core.http import StealthClient, PROFILES, attribution_scope

    def handler(request):
        return httpx.Response(200, json={"ExposedBreaches": {"breaches_details": [
            {"breach": "BigLeak", "xposed_date": "2019", "xposed_data": "Emails"}]}})

    sc = StealthClient(profile=PROFILES["off"], pool=["http://proxy:8080"])
    sc._clients["http://proxy:8080"] = httpx.AsyncClient(
        transport=httpx.MockTransport(handler))

    api = S.XposedOrNotAPI(_Cfg())
    api._stealth = sc
    with attribution_scope() as led:
        out = await api.search("jane@example.com")
    assert out and out[0]["type"] == "breach_data"
    assert led.proxied == 1 and led.direct == 0


def test_offline_phone_source_is_not_stealth_routed():
    # Offline libphonenumber makes no request, so it must not carry the flag.
    assert S.PhoneIntelAPI.STEALTH_ROUTED is False
    assert S.XposedOrNotAPI.STEALTH_ROUTED is True


# ── registration + posture ────────────────────────────────────────────────────

def test_all_new_sources_registered_keyless():
    reg = get_registered_apis()
    for name in ("xposedornot", "github_harvest", "gitlab", "wikidata",
                 "webfinger", "phone_intel", "openfec", "opencorporates"):
        cls = reg.get(name)
        assert cls is not None, f"{name} not registered"
        assert cls.REQUIRES_KEY is False
        assert APICategory.PEOPLE in cls.CATEGORIES
