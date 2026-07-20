"""
PhantomSignal — Keyless identity intel sources.

A cluster of no-API-key public sources that feed the people aggregator's
existing fields (emails, names, phones, employers, locations, breaches, social
links). Every source degrades to ``[]`` on the wrong identifier shape or on any
error, so they compose safely in the parallel people scan.

OPSEC note: all of these are third-party lookups and therefore *attributable*
egress — except ``phone_intel``, which is fully offline (libphonenumber
metadata, zero network) and adds nothing to a scan's attribution surface.

Parsing is split into pure module-level helpers (unit-tested) from the network
plumbing (the ``BaseIntelAPI`` subclasses).

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from phantomsignal.intel.apis.base import (
    APICategory, APITier, BaseIntelAPI, register_api,
)

# ── Identifier shape detection ────────────────────────────────────────────────
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,38}$")
_PHONE_RE = re.compile(r"^\+?[\d][\d\s\-().]{6,}$")
# Mail providers that never serve WebFinger — skip to avoid pointless requests.
_MAIL_ONLY_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "live.com", "icloud.com", "me.com", "proton.me", "protonmail.com",
    "aol.com", "gmx.com", "mail.com", "zoho.com",
}


def is_email(q: str) -> bool:
    return bool(_EMAIL_RE.match((q or "").strip()))


def is_phone(q: str) -> bool:
    q = (q or "").strip()
    return bool(_PHONE_RE.match(q)) and sum(c.isdigit() for c in q) >= 7


def is_username(q: str) -> bool:
    q = (q or "").strip()
    return bool(_USERNAME_RE.match(q)) and not is_email(q)


def looks_like_name(q: str) -> bool:
    q = (q or "").strip()
    return (" " in q) and not is_email(q) and not is_phone(q) and "/" not in q


# ── Pure parsers ──────────────────────────────────────────────────────────────

def parse_xposed(payload: Dict, email: str) -> List[Dict]:
    """XposedOrNot breach-analytics → normalized breach dicts (name/breach_date/
    pwn_count/data_classes), matching what the merge + results template expect."""
    if not isinstance(payload, dict):
        return []
    exposed = payload.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    breaches: List[Dict] = []
    for bd in (details or []):
        if not isinstance(bd, dict):
            continue
        raw_classes = bd.get("xposed_data") or ""
        data_classes = [c.strip() for c in re.split(r"[;,]", str(raw_classes)) if c.strip()]
        breaches.append({
            "name": bd.get("breach") or bd.get("breach_name") or "Unknown",
            "breach_date": bd.get("xposed_date") or bd.get("breach_date"),
            "pwn_count": bd.get("xposed_records"),
            "data_classes": data_classes,
            "domain": bd.get("domain"),
            "source": "xposedornot",
        })
    # Fallback: summary-only shape (semicolon-joined breach names, no details).
    if not breaches:
        summary = payload.get("BreachesSummary") or {}
        site = summary.get("site") if isinstance(summary, dict) else None
        for name in re.split(r"[;,]", str(site or "")):
            name = name.strip()
            if name:
                breaches.append({"name": name, "source": "xposedornot",
                                 "data_classes": []})
    return breaches


def parse_gitlab(user: Dict) -> Optional[Dict]:
    if not isinstance(user, dict) or not user.get("username"):
        return None
    emails = [user["public_email"]] if user.get("public_email") else []
    urls = [{"url": u} for u in (user.get("web_url"), user.get("website_url")) if u]
    return {
        "username": user.get("username"),
        "names": [user["name"]] if user.get("name") else [],
        "emails": emails,
        "location": user.get("location"),
        "company": user.get("organization"),
        "bio": user.get("bio"),
        "urls": urls,
        "twitter": user.get("twitter"),
    }


def _wd_claim_value(entity: Dict, prop: str):
    try:
        snak = entity["claims"][prop][0]["mainsnak"]
        return snak["datavalue"]["value"]
    except (KeyError, IndexError, TypeError):
        return None


def _wd_is_human(entity: Dict) -> bool:
    try:
        for claim in entity["claims"].get("P31", []):
            if claim["mainsnak"]["datavalue"]["value"].get("id") == "Q5":
                return True
    except (KeyError, TypeError):
        pass
    return False


def parse_wikidata(entity_json: Dict, qid: str) -> Optional[Dict]:
    """Wikidata EntityData JSON → identity dict. Returns None if the entity is
    not a human (avoids matching a band/company/film sharing the name)."""
    try:
        entity = entity_json["entities"][qid]
    except (KeyError, TypeError):
        return None
    if not _wd_is_human(entity):
        return None

    label = None
    try:
        label = entity["labels"]["en"]["value"]
    except (KeyError, TypeError):
        pass
    description = None
    try:
        description = entity["descriptions"]["en"]["value"]
    except (KeyError, TypeError):
        pass

    dob = None
    dob_val = _wd_claim_value(entity, "P569")
    if isinstance(dob_val, dict):
        m = re.match(r"[+-](\d{4})", str(dob_val.get("time", "")))
        if m:
            dob = m.group(1)

    urls: List[Dict] = []
    site = _wd_claim_value(entity, "P856")
    if isinstance(site, str):
        urls.append({"url": site})
    gh = _wd_claim_value(entity, "P2037")
    if isinstance(gh, str):
        urls.append({"url": f"https://github.com/{gh}"})
    tw = _wd_claim_value(entity, "P2002")
    if isinstance(tw, str):
        urls.append({"url": f"https://twitter.com/{tw}"})

    return {
        "qid": qid,
        "names": [label] if label else [],
        "bio": description,
        "dob": dob,
        "urls": urls,
    }


def parse_webfinger(payload: Dict) -> Optional[Dict]:
    if not isinstance(payload, dict) or "links" not in payload:
        return None
    urls: List[Dict] = []
    for link in payload.get("links", []):
        if not isinstance(link, dict):
            continue
        rel = link.get("rel", "")
        href = link.get("href")
        if href and rel in (
            "http://webfinger.net/rel/profile-page", "self",
        ):
            urls.append({"url": href})
    aliases = [a for a in payload.get("aliases", []) if isinstance(a, str)]
    if not urls and not aliases:
        return None
    return {"subject": payload.get("subject"), "urls": urls, "aliases": aliases}


def parse_fec(results: List[Dict], name: str) -> Optional[Dict]:
    """openFEC schedule_a contributions → distinct employer/occupation/location."""
    employers, occupations, locations, addresses = [], [], [], []
    seen_addr = set()
    contributor = name
    for r in (results or []):
        if not isinstance(r, dict):
            continue
        contributor = r.get("contributor_name") or contributor
        emp = r.get("contributor_employer")
        if emp and emp not in employers and emp.upper() not in {"NONE", "N/A", "SELF-EMPLOYED", "RETIRED"}:
            employers.append(emp)
        occ = r.get("contributor_occupation")
        if occ and occ not in occupations:
            occupations.append(occ)
        city, state = r.get("contributor_city"), r.get("contributor_state")
        if city and state:
            loc = f"{city.title()}, {state}"
            if loc not in locations:
                locations.append(loc)
            akey = (city, state, r.get("contributor_zip"))
            if akey not in seen_addr:
                seen_addr.add(akey)
                addresses.append({"city": city.title(), "state": state,
                                  "zip": r.get("contributor_zip")})
    if not (employers or occupations or locations):
        return None
    return {
        "names": [contributor] if contributor else [],
        "employers": employers[:5],
        "occupation": occupations[0] if occupations else None,
        "location": locations[0] if locations else None,
        "addresses": addresses[:5],
    }


def parse_opencorporates(payload: Dict, name: str) -> Optional[Dict]:
    try:
        officers = payload["results"]["officers"]
    except (KeyError, TypeError):
        return None
    employers, urls, officer_name = [], [], None
    for entry in (officers or []):
        off = entry.get("officer", {}) if isinstance(entry, dict) else {}
        officer_name = off.get("name") or officer_name
        company = off.get("company", {}) or {}
        cname = company.get("name")
        if cname:
            job = {"name": cname, "role": off.get("position"),
                   "jurisdiction": company.get("jurisdiction_code")}
            if job not in employers:
                employers.append(job)
        curl = company.get("opencorporates_url")
        if curl and {"url": curl} not in urls:
            urls.append({"url": curl})
    if not employers:
        return None
    return {"names": [officer_name or name], "employers": employers[:10],
            "urls": urls[:10]}


# ── Offline phone intel (libphonenumber) ─────────────────────────────────────
_PHONE_TYPE_NAMES = {
    0: "fixed_line", 1: "mobile", 2: "fixed_line_or_mobile", 3: "toll_free",
    4: "premium_rate", 5: "shared_cost", 6: "voip", 7: "personal_number",
    8: "pager", 9: "uan", 10: "voicemail",
}


def phone_intel(query: str) -> List[Dict]:
    """Offline phone enrichment via libphonenumber metadata — no network. Returns
    a ``phone_validation`` result the aggregator's merge already understands."""
    if not is_phone(query):
        return []
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder
    except ImportError:
        return []

    raw = query.strip()
    num = None
    for region in (None, "US"):
        try:
            num = phonenumbers.parse(raw, region)
            if phonenumbers.is_possible_number(num):
                break
        except phonenumbers.NumberParseException:
            num = None
    if num is None or not phonenumbers.is_valid_number(num):
        return []

    ntype = phonenumbers.number_type(num)
    data = {
        "phone": phonenumbers.format_number(
            num, phonenumbers.PhoneNumberFormat.E164),
        "valid": True,
        "type": _PHONE_TYPE_NAMES.get(ntype, "unknown"),
        "carrier": carrier.name_for_number(num, "en") or None,
        "country_name": geocoder.description_for_number(num, "en") or None,
        "region_code": phonenumbers.region_code_for_number(num),
        "source_offline": True,
    }
    return [{
        "type": "phone_validation", "source": "phone_intel", "data": data,
        "confidence": 0.95, "relevance_score": 0.8, "is_anomaly": False,
        "tags": ["phone", "identity", "offline"],
    }]


# ── API classes ───────────────────────────────────────────────────────────────

@register_api
class XposedOrNotAPI(BaseIntelAPI):
    NAME = "xposedornot"
    DESCRIPTION = "Keyless breach lookup by email (XposedOrNot) — no HIBP key"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.EMAIL, APICategory.BREACH, APICategory.PEOPLE]
    BASE_URL = "https://api.xposedornot.com/v1"
    DOCS_URL = "https://xposedornot.com/api_doc"
    RATE_LIMIT_PER_MINUTE = 20

    async def search(self, query: str, **kwargs) -> List[Dict]:
        email = (query or "").strip().lower()
        if not is_email(email):
            return []
        payload = await self._get(f"{self.BASE_URL}/breach-analytics",
                                  params={"email": email})
        breaches = parse_xposed(payload, email)
        if not breaches:
            return []
        return [self._wrap_result(
            "breach_data",
            {"email": email, "breached": True, "breaches": breaches},
            confidence=0.85, relevance_score=0.9,
            tags=["breach", "email", "identity"], is_anomaly=True,
        )]


@register_api
class GitHubCommitHarvesterAPI(BaseIntelAPI):
    NAME = "github_harvest"
    DESCRIPTION = "GitHub commit-email harvester — real name/email from commits"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://api.github.com"
    DOCS_URL = "https://docs.github.com/en/rest"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        login = (query or "").strip()
        if not is_username(login):
            return []
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self._api_key:
            headers["Authorization"] = f"token {self._api_key}"

        user = await self._get(f"{self.BASE_URL}/users/{login}", headers=headers)
        if not isinstance(user, dict) or "login" not in user:
            return []
        login = user["login"]

        emails, names = set(), set()
        if user.get("name"):
            names.add(user["name"])

        repos = await self._get(
            f"{self.BASE_URL}/users/{login}/repos",
            params={"per_page": 100, "sort": "pushed"}, headers=headers)
        repo_names = [r.get("name") for r in (repos if isinstance(repos, list) else [])
                      if isinstance(r, dict) and not r.get("fork")][:8]

        for repo in repo_names:
            commits = await self._get(
                f"{self.BASE_URL}/repos/{login}/{repo}/commits",
                params={"author": login, "per_page": 30}, headers=headers)
            for c in (commits if isinstance(commits, list) else []):
                author = (c.get("commit", {}) or {}).get("author", {}) or {}
                self._collect(author, emails, names)

        events = await self._get(f"{self.BASE_URL}/users/{login}/events/public",
                                 params={"per_page": 30}, headers=headers)
        for event in (events if isinstance(events, list) else []):
            for commit in (event.get("payload", {}) or {}).get("commits", []):
                self._collect(commit.get("author", {}) or {}, emails, names)

        if not emails and not names:
            return []
        return [self._wrap_result(
            "github_commit_identity",
            {"username": login, "emails": sorted(emails), "names": sorted(names),
             "company": user.get("company"), "location": user.get("location"),
             "repos_scanned": len(repo_names)},
            confidence=0.9, relevance_score=0.85,
            tags=["github", "email", "identity", "harvest"],
            is_anomaly=bool(emails),
        )]

    @staticmethod
    def _collect(author: Dict, emails: set, names: set) -> None:
        email = (author.get("email") or "").strip().lower()
        if email and "noreply" not in email and is_email(email):
            emails.add(email)
        name = (author.get("name") or "").strip()
        if name and not is_email(name):
            names.add(name)


@register_api
class GitLabAPI(BaseIntelAPI):
    NAME = "gitlab"
    DESCRIPTION = "GitLab public user OSINT — profile, links, public email"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE]
    BASE_URL = "https://gitlab.com/api/v4"
    DOCS_URL = "https://docs.gitlab.com/ee/api/users.html"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        username = (query or "").strip()
        if not is_username(username):
            return []
        found = await self._get(f"{self.BASE_URL}/users",
                                params={"username": username})
        if not isinstance(found, list) or not found:
            return []
        uid = found[0].get("id")
        full = await self._get(f"{self.BASE_URL}/users/{uid}")
        data = parse_gitlab(full if isinstance(full, dict) else found[0])
        if not data:
            return []
        return [self._wrap_result(
            "gitlab_profile", data, confidence=0.9, relevance_score=0.75,
            tags=["gitlab", "social", "developer"],
        )]


@register_api
class WikidataAPI(BaseIntelAPI):
    NAME = "wikidata"
    DESCRIPTION = "Wikidata structured identity for named people (DOB, links)"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://www.wikidata.org"
    DOCS_URL = "https://www.wikidata.org/wiki/Wikidata:REST_API"
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        name = (query or "").strip()
        if not looks_like_name(name):
            return []
        hits = await self._get(
            f"{self.BASE_URL}/w/api.php",
            params={"action": "wbsearchentities", "search": name,
                    "language": "en", "format": "json", "type": "item",
                    "limit": 1})
        try:
            qid = hits["search"][0]["id"]
        except (KeyError, IndexError, TypeError):
            return []
        entity = await self._get(
            f"{self.BASE_URL}/wiki/Special:EntityData/{qid}.json")
        data = parse_wikidata(entity, qid)
        if not data:
            return []
        return [self._wrap_result(
            "wikidata_identity", data, confidence=0.8, relevance_score=0.8,
            tags=["wikidata", "identity", "biographical"],
        )]


@register_api
class WebFingerAPI(BaseIntelAPI):
    NAME = "webfinger"
    DESCRIPTION = "WebFinger resolution — fediverse handle → profile + aliases"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE
    CATEGORIES = [APICategory.SOCIAL, APICategory.PEOPLE, APICategory.EMAIL]
    RATE_LIMIT_PER_MINUTE = 30

    async def search(self, query: str, **kwargs) -> List[Dict]:
        acct = (query or "").strip().lstrip("@")
        if "@" not in acct:
            return []
        domain = acct.rsplit("@", 1)[1].lower()
        if not domain or domain in _MAIL_ONLY_DOMAINS:
            return []
        payload = await self._get(
            f"https://{domain}/.well-known/webfinger",
            params={"resource": f"acct:{acct}"})
        data = parse_webfinger(payload)
        if not data:
            return []
        return [self._wrap_result(
            "webfinger_identity", data, confidence=0.85, relevance_score=0.7,
            tags=["webfinger", "fediverse", "identity"],
        )]


@register_api
class PhoneIntelAPI(BaseIntelAPI):
    NAME = "phone_intel"
    DESCRIPTION = "Offline phone metadata (libphonenumber) — zero network egress"
    REQUIRES_KEY = False
    TIER = APITier.FREE
    CATEGORIES = [APICategory.PEOPLE]
    RATE_LIMIT_PER_MINUTE = 600

    async def search(self, query: str, **kwargs) -> List[Dict]:
        return phone_intel(query)


@register_api
class OpenFECAPI(BaseIntelAPI):
    NAME = "openfec"
    DESCRIPTION = "US political donations (openFEC) — name → employer/occupation"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://api.open.fec.gov/v1"
    DOCS_URL = "https://api.open.fec.gov/developers/"
    SIGN_UP_URL = "https://api.data.gov/signup/"
    RATE_LIMIT_PER_MINUTE = 20

    async def search(self, query: str, **kwargs) -> List[Dict]:
        name = (query or "").strip()
        if not looks_like_name(name):
            return []
        key = self.config.get_api_key("openfec") or "DEMO_KEY"
        payload = await self._get(
            f"{self.BASE_URL}/schedules/schedule_a/",
            params={"contributor_name": name, "api_key": key,
                    "per_page": 20, "sort": "-contribution_receipt_date"})
        results = payload.get("results") if isinstance(payload, dict) else None
        data = parse_fec(results or [], name)
        if not data:
            return []
        return [self._wrap_result(
            "fec_contribution", data, confidence=0.6, relevance_score=0.65,
            tags=["fec", "employer", "identity", "us"],
        )]


@register_api
class OpenCorporatesAPI(BaseIntelAPI):
    NAME = "opencorporates"
    DESCRIPTION = "Company officers (OpenCorporates) — name → companies/roles"
    REQUIRES_KEY = False
    STEALTH_ROUTED = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.PEOPLE]
    BASE_URL = "https://api.opencorporates.com/v0.4"
    DOCS_URL = "https://api.opencorporates.com/documentation/API-Reference"
    RATE_LIMIT_PER_MINUTE = 20

    async def search(self, query: str, **kwargs) -> List[Dict]:
        name = (query or "").strip()
        if not looks_like_name(name):
            return []
        params = {"q": name, "per_page": 10}
        token = self.config.get_api_key("opencorporates")
        if token:
            params["api_token"] = token
        payload = await self._get(f"{self.BASE_URL}/officers/search",
                                  params=params)
        data = parse_opencorporates(payload, name)
        if not data:
            return []
        return [self._wrap_result(
            "opencorporates_officer", data, confidence=0.55,
            relevance_score=0.6, tags=["opencorporates", "employer", "identity"],
        )]
