"""
PhantomSignal Identity Routes — turn the lens on the operator.

Shows what *you* leak when you're online: the request your browser sent to this
app, an egress/network check run through your configured scan egress (so the IP,
geo, and TLS fingerprint shown are what a target actually sees), and a
client-side browser fingerprint (UA, WebGL, canvas, WebRTC local-IP leak).
"""
from __future__ import annotations

import asyncio

from flask import Blueprint, jsonify, render_template, request

from phantomsignal.core.config import config

identity_bp = Blueprint("identity", __name__)

# Header names worth surfacing as "what your browser told this server".
_INTERESTING_HEADERS = [
    "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer",
    "DNT", "Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile",
    "Sec-Fetch-Site", "Sec-Fetch-Mode", "Upgrade-Insecure-Requests",
    "X-Forwarded-For", "Via", "Connection",
]


@identity_bp.route("/")
def identity_page():
    headers = [(h, request.headers.get(h)) for h in _INTERESTING_HEADERS
               if request.headers.get(h)]
    return render_template(
        "identity.html",
        req_headers=headers,
        remote_addr=request.headers.get("X-Forwarded-For") or request.remote_addr,
    )


def _stealth_posture() -> dict:
    """Reflect the current scan-egress configuration (no network call)."""
    from phantomsignal.core.http import resolve_profile, resolve_egress, _CURL_AVAILABLE, _IMPERSONATE
    prof = resolve_profile(config)
    egress, rotation = resolve_egress(config)
    impersonate = bool(config.get("scraper", "tls_impersonate", default=False)) and _CURL_AVAILABLE
    proxies = [p for p in egress if p]
    return {
        "profile": prof.name,
        "proxied": bool(proxies),
        "proxy_count": len(proxies),
        "rotation": rotation if len(egress) > 1 else None,
        "impersonate": impersonate,
        "impersonate_as": _IMPERSONATE[0] if impersonate else None,
    }


async def _egress_check() -> dict:
    """Run IP/geo + TLS-fingerprint lookups through the configured stealth
    egress, so the result is what a scan target would observe."""
    from phantomsignal.core.http import stealth_client

    out: dict = {"stealth": _stealth_posture(), "egress": None, "tls": None, "errors": []}

    async def geo():
        fields = ("status,message,query,country,countryCode,regionName,city,zip,"
                  "lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting")
        async with stealth_client(config, timeout=8, verify=True) as c:
            r = await c.get(f"http://ip-api.com/json/?fields={fields}")
            return r.json()

    async def tls():
        async with stealth_client(config, timeout=8, verify=True) as c:
            r = await c.get("https://tls.browserleaks.com/json")
            return r.json()

    geo_res, tls_res = await asyncio.gather(geo(), tls(), return_exceptions=True)

    if isinstance(geo_res, dict) and geo_res.get("status") == "success":
        out["egress"] = {
            "ip": geo_res.get("query"),
            "city": geo_res.get("city"),
            "region": geo_res.get("regionName"),
            "zip": geo_res.get("zip"),
            "country": geo_res.get("country"),
            "country_code": geo_res.get("countryCode"),
            "lat": geo_res.get("lat"),
            "lon": geo_res.get("lon"),
            "timezone": geo_res.get("timezone"),
            "isp": geo_res.get("isp"),
            "org": geo_res.get("org"),
            "asn": geo_res.get("as") or geo_res.get("asname"),
            "flags": {
                "proxy": geo_res.get("proxy"),
                "hosting": geo_res.get("hosting"),
                "mobile": geo_res.get("mobile"),
            },
        }
    else:
        out["errors"].append("geo lookup failed")

    if isinstance(tls_res, dict):
        out["tls"] = {
            "ja3": tls_res.get("ja3_hash"),
            "ja4": tls_res.get("ja4"),
            "seen_ua": tls_res.get("user_agent"),
        }
    else:
        out["errors"].append("tls fingerprint lookup failed")

    return out


@identity_bp.route("/egress")
def egress():
    """JSON: the network/TLS identity your scans present, fetched live."""
    try:
        loop = asyncio.new_event_loop()
        data = loop.run_until_complete(asyncio.wait_for(_egress_check(), timeout=20))
        loop.close()
        return jsonify({"status": "ok", "data": data})
    except Exception as e:  # noqa: BLE001 - surface any failure to the UI
        return jsonify({"status": "error", "message": str(e)}), 200
